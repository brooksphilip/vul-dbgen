package chainguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	baseURL      = "https://advisories.cgr.dev/chainguard/v2/osv/"
	indexURL     = baseURL + "all.json"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	// Both Chainguard and Wolfi use rolling releases
	rollingVersion = "rolling"
	// Concurrency limit for fetching individual advisories
	concurrencyLimit = 10
)

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type ChainguardFetcher struct{}

// IndexEntry represents an entry in the all.json index
type IndexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// OSVAdvisory represents a single OSV advisory
type OSVAdvisory struct {
	ID        string        `json:"id"`
	Published string        `json:"published"`
	Modified  string        `json:"modified"`
	Severity  []OSVSeverity `json:"severity"`
	Upstream  []string      `json:"upstream"`
	Affected  []OSVAffected `json:"affected"`
}

// OSVSeverity represents severity information
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected represents affected package information
type OSVAffected struct {
	Package           OSVPackage        `json:"package"`
	Ranges            []OSVRange        `json:"ranges"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

// OSVPackage represents package information
type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// OSVRange represents version range information
type OSVRange struct {
	Type   string      `json:"type"`
	Events []OSVEvent  `json:"events"`
}

// OSVEvent represents a version event (introduced, fixed, etc.)
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// EcosystemSpecific contains ecosystem-specific information
type EcosystemSpecific struct {
	Components []Component `json:"components"`
}

// Component represents a component within an advisory
type Component struct {
	ID                string `json:"id"`
	LatestEventStatus string `json:"latest_event_status"`
}

func init() {
	updater.RegisterFetcher("chainguard", &ChainguardFetcher{})
}

func (f *ChainguardFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Chainguard").Info("Start fetching vulnerabilities")

	// Fetch the index
	index, err := f.fetchIndex()
	if err != nil {
		return resp, err
	}

	log.WithField("advisories", len(index)).Info("Fetched advisory index")

	// Fetch individual advisories concurrently
	vulns := f.fetchAdvisories(index)

	resp.Vulnerabilities = vulns

	// Count by namespace for logging
	chainguardCount := 0
	wolfiCount := 0
	for _, v := range vulns {
		for _, fv := range v.FixedIn {
			if strings.HasPrefix(fv.Feature.Namespace, "chainguard:") {
				chainguardCount++
			} else if strings.HasPrefix(fv.Feature.Namespace, "wolfi:") {
				wolfiCount++
			}
		}
	}

	log.WithFields(log.Fields{
		"total":      len(vulns),
		"chainguard": chainguardCount,
		"wolfi":      wolfiCount,
	}).Info("fetching chainguard done")

	return resp, nil
}

func (f *ChainguardFetcher) fetchIndex() ([]IndexEntry, error) {
	r, err := http.Get(indexURL)
	if err != nil {
		log.WithError(err).WithField("url", indexURL).Error("Failed to download chainguard index")
		return nil, err
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read chainguard index body")
		return nil, err
	}

	var index []IndexEntry
	if err := json.Unmarshal(body, &index); err != nil {
		log.WithError(err).Error("Failed to unmarshal chainguard index")
		return nil, err
	}

	return index, nil
}

func (f *ChainguardFetcher) fetchAdvisories(index []IndexEntry) []common.Vulnerability {
	var vulns []common.Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for concurrency limit
	sem := make(chan struct{}, concurrencyLimit)

	for _, entry := range index {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			advisory, err := f.fetchAdvisory(id)
			if err != nil {
				log.WithError(err).WithField("id", id).Warn("Failed to fetch advisory, skipping")
				return
			}

			advisoryVulns := f.parseAdvisory(advisory)
			if len(advisoryVulns) > 0 {
				mu.Lock()
				vulns = append(vulns, advisoryVulns...)
				mu.Unlock()
			}
		}(entry.ID)
	}

	wg.Wait()
	return vulns
}

func (f *ChainguardFetcher) fetchAdvisory(id string) (*OSVAdvisory, error) {
	url := fmt.Sprintf("%s%s.json", baseURL, id)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", r.StatusCode)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var advisory OSVAdvisory
	if err := json.Unmarshal(body, &advisory); err != nil {
		return nil, err
	}

	return &advisory, nil
}

func (f *ChainguardFetcher) parseAdvisory(advisory *OSVAdvisory) []common.Vulnerability {
	var vulns []common.Vulnerability

	// Extract CVE from upstream array
	var cveName string
	for _, upstream := range advisory.Upstream {
		if strings.HasPrefix(upstream, "CVE-") && cveRegex.MatchString(upstream) {
			cveName = upstream
			break
		}
	}

	// Skip if no CVE found
	if cveName == "" {
		return nil
	}

	// Validate CVE year
	if year, err := common.ParseYear(cveName[4:]); err != nil {
		log.WithField("cve", cveName).Warn("Unable to parse year from CVE name")
		return nil
	} else if year < common.FirstYear {
		return nil
	}

	// Extract CVSS vector if available
	var cvssVector string
	for _, sev := range advisory.Severity {
		if sev.Type == "CVSS_V3" && sev.Score != "" {
			cvssVector = sev.Score
			break
		}
	}

	// Track seen package+namespace combinations to dedupe across architectures
	seen := make(map[string]bool)

	for _, affected := range advisory.Affected {
		// Map ecosystem to namespace
		var namespace string
		switch affected.Package.Ecosystem {
		case "Chainguard":
			namespace = "chainguard:" + rollingVersion
		case "Wolfi":
			namespace = "wolfi:" + rollingVersion
		default:
			continue // Skip unknown ecosystems
		}

		// Check if this package has a fixed status
		hasFixed := false
		for _, comp := range affected.EcosystemSpecific.Components {
			if comp.LatestEventStatus == "fixed" {
				hasFixed = true
				break
			}
		}
		if !hasFixed {
			continue
		}

		// Extract fixed version from ranges
		var fixedVersion string
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					fixedVersion = event.Fixed
					break
				}
			}
			if fixedVersion != "" {
				break
			}
		}

		if fixedVersion == "" {
			continue
		}

		// Dedupe by package name + namespace (same package appears for multiple architectures)
		key := fmt.Sprintf("%s:%s:%s", namespace, affected.Package.Name, cveName)
		if seen[key] {
			continue
		}
		seen[key] = true

		ver, err := common.NewVersion(fixedVersion)
		if err != nil {
			log.WithError(err).WithField("version", fixedVersion).Warn("Failed to parse package version, skipping")
			continue
		}

		var vuln common.Vulnerability
		vuln.Name = cveName
		vuln.Link = cveURLPrefix + cveName

		// Store CVSS vector - NVD enrichment will provide the score
		if cvssVector != "" {
			if strings.HasPrefix(cvssVector, "CVSS:3") {
				vuln.CVSSv3 = common.CVSS{Vectors: cvssVector}
			}
		}

		featureVersion := common.FeatureVersion{
			Feature: common.Feature{
				Namespace: namespace,
				Name:      affected.Package.Name,
			},
			Version: ver,
		}
		vuln.FixedIn = append(vuln.FixedIn, featureVersion)

		vulns = append(vulns, vuln)

		common.DEBUG_VULN(&vuln, "chainguard")
	}

	return vulns
}

func (f *ChainguardFetcher) Clean() {
	// No cleanup needed for chainguard fetcher
}
