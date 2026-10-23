package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// `proxygo xai video "<prompt>"` — port of
// cli/src/cli/commands/xaiVideo.js: generate a video with Grok Imagine
// through the LOCAL proxygo gateway (POST /v1/videos/generations),
// poll until done, and download the file. Uses the proxygo API key
// (--api-key or env PROXYGO_API_KEY) and the gateway's public
// /v1/videos routes the same way scripts/xai-video-test.sh does.

var xaiVideoHelp = `
Usage: proxygo xai video "<prompt>" [options]

Generate a video with xAI Grok Imagine through the LOCAL proxygo gateway.

Examples:
  proxygo xai video "a lighthouse at dawn, ocean waves, cinematic"
  proxygo xai video "a neon city flyover" --duration 10 --aspect-ratio 16:9
  proxygo xai video "animate this" --image ./photo.jpg --output city.mp4

Options:
  --output <path>        Output file (default: grok-video-<timestamp>.mp4)
  --model <id>           Video model (default: xai/grok-imagine-video)
  --duration <sec>       Video length in seconds
  --aspect-ratio <r>     e.g. 16:9, 9:16, 1:1
  --resolution <r>       e.g. 720p, 480p
  --image <path|url>     Image to animate (local file or URL)
  --timeout <sec>        Max wait for generation (default: 600)
  --api-key <key>        proxygo API key (default: env PROXYGO_API_KEY)
  --host <host>          Gateway host (default: 127.0.0.1)
  --port <port>          Gateway port (default: 20128)
  -h, --help             Show this help
`

type xaiOptions struct {
	prompt       string
	output       string
	model        string
	duration     string
	aspectRatio  string
	resolution   string
	image        string
	timeoutSec   int
	apiKey       string
	host         string
	port         int
	pollInterval time.Duration
	help         bool
}

func parseXaiVideoArgs(args []string) (xaiOptions, error) {
	opts := xaiOptions{
		model:        "xai/grok-imagine-video",
		timeoutSec:   600,
		apiKey:       os.Getenv("PROXYGO_API_KEY"),
		host:         "127.0.0.1",
		port:         20128,
		pollInterval: 5000 * time.Millisecond,
	}
	var positional []string
	next := func(a string, i *int) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("missing value for %s", a)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		var err error
		switch a {
		case "-h", "--help":
			opts.help = true
		case "--output":
			opts.output, err = next(a, &i)
		case "--model":
			opts.model, err = next(a, &i)
		case "--duration":
			opts.duration, err = next(a, &i)
		case "--aspect-ratio":
			opts.aspectRatio, err = next(a, &i)
		case "--resolution":
			opts.resolution, err = next(a, &i)
		case "--image":
			opts.image, err = next(a, &i)
		case "--api-key":
			opts.apiKey, err = next(a, &i)
		case "--host":
			opts.host, err = next(a, &i)
		case "--timeout":
			var v string
			v, err = next(a, &i)
			if err == nil {
				var n int
				if _, serr := fmt.Sscanf(v, "%d", &n); serr != nil || n <= 0 {
					err = fmt.Errorf("invalid --timeout: %s", v)
				} else {
					opts.timeoutSec = n
				}
			}
		case "--port":
			var v string
			v, err = next(a, &i)
			if err == nil {
				var n int
				if _, serr := fmt.Sscanf(v, "%d", &n); serr != nil || n <= 0 {
					err = fmt.Errorf("invalid --port: %s", v)
				} else {
					opts.port = n
				}
			}
		case "--poll-interval-ms": // hidden test knob, ported from the JS parse
			var v string
			v, err = next(a, &i)
			if err == nil {
				var n int
				if _, serr := fmt.Sscanf(v, "%d", &n); serr != nil || n < 1 {
					err = fmt.Errorf("invalid --poll-interval-ms: %s", v)
				} else {
					opts.pollInterval = time.Duration(n) * time.Millisecond
				}
			}
		default:
			if strings.HasPrefix(a, "-") {
				return opts, fmt.Errorf("unknown option: %s", a)
			}
			positional = append(positional, a)
		}
		if err != nil {
			return opts, err
		}
	}
	opts.prompt = strings.Join(positional, " ")
	if opts.output == "" {
		opts.output = fmt.Sprintf("grok-video-%d.mp4", time.Now().UnixMilli())
	}
	if opts.prompt == "" && !opts.help {
		return opts, fmt.Errorf("prompt is required")
	}
	return opts, nil
}

var bearerPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]+`)

// sanitizeText redacts bearer tokens from upstream-controlled error
// text before printing (JS sanitizeText).
func sanitizeText(v any, apiKey string) string {
	s := ""
	switch t := v.(type) {
	case string:
		s = t
	case nil:
		s = ""
	default:
		raw, _ := json.Marshal(t)
		s = string(raw)
	}
	s = bearerPattern.ReplaceAllString(s, "Bearer [redacted]")
	if apiKey != "" {
		s = strings.ReplaceAll(s, apiKey, "[redacted]")
	}
	return s
}

func resolveImageInput(image string) (string, error) {
	if image == "" {
		return "", nil
	}
	if strings.HasPrefix(image, "http://") || strings.HasPrefix(image, "https://") || strings.HasPrefix(image, "data:") {
		return image, nil
	}
	ext := strings.ToLower(filepath.Ext(image))
	mime := map[string]string{".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}[ext]
	if mime == "" {
		return "", fmt.Errorf("--image file must be png, webp, jpg, or jpeg")
	}
	raw, err := os.ReadFile(image)
	if err != nil {
		return "", fmt.Errorf("cannot read --image file: %v", err)
	}
	return fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(raw)), nil
}

// Direct transport (JS fetch parity): the gateway is loopback/LAN.
var xaiHTTPClient = &http.Client{Transport: &http.Transport{Proxy: nil}}

type xaiResponse struct {
	status     int
	headers    http.Header
	data       map[string]any
	retryAfter string
}

func xaiRequest(method, url string, body any, apiKey string, timeout time.Duration, extra map[string]string) (xaiResponse, error) {
	var out xaiResponse
	var reader io.Reader
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return out, err
		}
		reader = strings.NewReader(string(raw))
		headers["Content-Type"] = "application/json"
	}
	if apiKey != "" {
		headers["Authorization"] = "Bearer " + apiKey
	}
	for k, v := range extra {
		headers[k] = v
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return out, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := xaiHTTPClient
	if timeout > 0 {
		c := *xaiHTTPClient
		c.Timeout = timeout
		client = &c
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out.status = resp.StatusCode
	out.headers = resp.Header
	out.retryAfter = resp.Header.Get("Retry-After")
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err == nil {
		out.data = data
	}
	return out, nil
}

func xaiErrorMessage(res xaiResponse, fallback string, apiKey string) string {
	detail := ""
	if res.data != nil {
		if e, ok := res.data["error"]; ok {
			if m, ok := e.(map[string]any); ok {
				detail = strOf(m["message"])
			} else {
				detail = strOf(e)
			}
		}
		if detail == "" {
			detail = strOf(res.data["message"])
		}
		if detail == "" {
			detail = strOf(res.data["detail"])
		}
	}
	msg := fallback
	if detail != "" {
		msg = fmt.Sprintf("%s (%d): %s", fallback, res.status, detail)
	} else {
		msg = fmt.Sprintf("%s failed with HTTP %d", fallback, res.status)
	}
	msg = sanitizeText(msg, apiKey)
	if res.status == 400 && strings.Contains(msg, "No credentials") {
		msg += "\nHint: connect xAI in the proxygo dashboard or check the provider connection."
	}
	return msg
}

var (
	terminalVideoStatuses = map[string]bool{"done": true, "failed": true, "completed": true, "error": true, "expired": true, "cancelled": true}
	failedVideoStatuses   = map[string]bool{"failed": true, "error": true, "expired": true, "cancelled": true}
)

func videoResultURL(data map[string]any) string {
	if data == nil {
		return ""
	}
	result := jsonChild(data, "result")
	video := jsonChild(result, "video")
	if u := strOf(video["url"]); u != "" {
		return u
	}
	return strOf(jsonChild(video, "file_output")["public_url"])
}

func downloadVideo(url, output, apiKey string) error {
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "video/*,*/*")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}
	part := output + ".part"
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(part)
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	if err := os.Rename(part, output); err != nil {
		os.Remove(part)
		return err
	}
	return nil
}

func cmdXaiVideo(args []string, stdout, stderr io.Writer) int {
	opts, err := parseXaiVideoArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "❌ xai video: %s\n", err)
		fmt.Fprint(stdout, xaiVideoHelp)
		return 1
	}
	if opts.help {
		fmt.Fprint(stdout, xaiVideoHelp)
		return 0
	}
	imageURL, err := resolveImageInput(opts.image)
	if err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		return 1
	}
	base := fmt.Sprintf("http://%s:%d", opts.host, opts.port)
	payload := map[string]any{"model": opts.model, "prompt": opts.prompt}
	if opts.duration != "" {
		var n int
		if _, serr := fmt.Sscanf(opts.duration, "%d", &n); serr == nil {
			payload["duration"] = n
		} else {
			payload["duration"] = opts.duration
		}
	}
	if opts.aspectRatio != "" {
		payload["aspect_ratio"] = opts.aspectRatio
	}
	if opts.resolution != "" {
		payload["resolution"] = opts.resolution
	}
	if imageURL != "" {
		payload["image"] = map[string]any{"url": imageURL}
	}

	partFile := opts.output + ".part"
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Fprintf(stderr, "\n❌ Interrupted. Partial download removed: %s\n", partFile)
		os.Remove(partFile)
		os.Exit(130)
	}()
	defer signal.Stop(sig)

	fmt.Fprintf(stdout, "🎬 Submitting video job to %s\n", base)
	fmt.Fprintf(stdout, "   model: %s\n", opts.model)
	create, err := xaiRequest("POST", base+"/v1/videos/generations", payload, opts.apiKey, 60*time.Second, nil)
	if err != nil {
		fmt.Fprintf(stderr, "❌ Video generation request failed: %v\n", err)
		fmt.Fprintln(stderr, "   Is the local proxygo gateway running? Start it with: proxygo")
		return 1
	}
	if create.status != 200 {
		fmt.Fprintf(stderr, "❌ %s\n", xaiErrorMessage(create, "Video generation request", opts.apiKey))
		return 1
	}
	requestID := strOf(create.data["request_id"])
	if requestID == "" {
		fmt.Fprintln(stderr, "❌ Video generation response did not include request_id")
		return 1
	}
	connectionID := create.headers.Get("x-proxygo-connection-id")
	fmt.Fprintf(stdout, "   request_id: %s\n", requestID)
	fmt.Fprintln(stdout, "⏳ Waiting for xAI to finish rendering…")

	deadline := time.Now().Add(time.Duration(opts.timeoutSec) * time.Second)
	var final map[string]any
	for {
		pollURL := fmt.Sprintf("%s/v1/videos/%s", base, requestID)
		var extra map[string]string
		if connectionID != "" {
			extra = map[string]string{"x-connection-id": connectionID}
		}
		res, perr := xaiRequest("GET", pollURL, nil, opts.apiKey, 30*time.Second, extra)
		if perr != nil {
			fmt.Fprintf(stderr, "❌ Polling failed: %v\n", perr)
			return 1
		}
		if res.status >= 400 && res.status != 429 && res.status != 503 {
			fmt.Fprintf(stderr, "❌ %s\n", xaiErrorMessage(res, "Video status request", opts.apiKey))
			return 1
		}
		status := "unknown"
		if res.data != nil && strOf(res.data["status"]) != "" {
			status = strOf(res.data["status"])
		}
		fmt.Fprintf(stdout, "   status: %s\n", status)
		if terminalVideoStatuses[status] {
			if failedVideoStatuses[status] {
				msg := "xAI video generation " + status
				if res.data != nil {
					if e, ok := res.data["error"]; ok {
						msg = sanitizeText(e, opts.apiKey)
					}
				}
				fmt.Fprintf(stderr, "❌ %s\n", msg)
				return 1
			}
			final = res.data
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(stderr, "❌ Timed out waiting for video after %ds. Request ID: %s\n", opts.timeoutSec, requestID)
			return 1
		}
		time.Sleep(opts.pollInterval)
	}
	videoURL := videoResultURL(final)
	if videoURL == "" {
		fmt.Fprintln(stderr, "❌ Video finished but no result URL was returned")
		return 1
	}
	fmt.Fprintf(stdout, "⬇ Downloading video → %s\n", opts.output)
	if err := downloadVideo(videoURL, opts.output, opts.apiKey); err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		return 1
	}
	abs, _ := filepath.Abs(opts.output)
	fmt.Fprintf(stdout, "✅ Saved video: %s\n", abs)
	return 0
}
