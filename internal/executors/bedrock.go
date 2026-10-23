package executors

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// BedrockExecutor ports open-sse/executors/bedrock.js: Amazon Bedrock
// runtime with per-request SigV4 signing. Wire format is Anthropic Messages
// ("bedrock", format claude) or OpenAI Chat Completions ("bedrock-xai",
// format openai) — one executor, registry format decides (same pattern as
// vertex/vertex-partner).
//
// Streaming arrives as AWS EventStream frames whose payloads are
// {"bytes": "<base64 of one Anthropic/OpenAI event>"}; frames are unwrapped
// back into SSE of the wire format here (same framing as kiro).
//
// Credential resolution: the JS resolves through shared/awsCredentials.js
// which can read local AWS profiles / SSO sessions via the AWS SDK. Stdlib
// Go has no SDK, so this port resolves, in order: providerSpecificData
// (accessKeyId/awsAccessKeyId, secretAccessKey, sessionToken, region),
// then the process env (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
// AWS_SESSION_TOKEN / AWS_REGION / AWS_DEFAULT_REGION). Named-profile and
// SSO resolution is a documented TODO for the parent (needs an SDK or a
// credentials-file parser adapter).
type BedrockExecutor struct {
	*Base
	providerID string
}

var bedrockRegionRe = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d+$`)

var bedrockFamilyPatterns = map[string]*regexp.Regexp{
	"claude": regexp.MustCompile(`(^|[./])anthropic\.`),
	"openai": regexp.MustCompile(`(^|[./])xai\.`),
}

var bedrockFamilyHints = map[string]string{
	"claude": `an Anthropic model, e.g. "us.anthropic.claude-sonnet-4-5-20250929-v1:0"`,
	"openai": `an xAI model, e.g. "us.xai.grok-4.6"`,
}

const bedrockAnthropicVersion = "bedrock-2023-05-31" // config/awsConstants.js BEDROCK.anthropicVersion

func NewBedrockExecutor(providerID string) *BedrockExecutor {
	if providerID == "" {
		providerID = "bedrock"
	}
	e := &BedrockExecutor{providerID: providerID}
	e.Base = &Base{ProviderID: providerID}
	return e
}

func (e *BedrockExecutor) wireFormat(p *ProviderInfo) string {
	if p != nil && p.Format != "" {
		return p.Format
	}
	return "openai" // JS: this.wireFormat = config.format || FORMATS.OPENAI
}

// resolveAWSCredentials implements the static-credential subset of
// shared/awsCredentials.js resolveAwsCredentials + resolveRegion (region is
// validated because it lands in the hostname — an unvalidated region would
// let a connection redirect signed traffic to an arbitrary origin).
func resolveAWSCredentials(cred Credential) (awsCredentials, error) {
	akid := cred.SpecificString("accessKeyId")
	if akid == "" {
		akid = cred.SpecificString("awsAccessKeyId")
	}
	secret := cred.SpecificString("secretAccessKey")
	if secret == "" {
		secret = cred.SpecificString("awsSecretAccessKey")
	}
	token := cred.SpecificString("sessionToken")
	if token == "" {
		token = cred.SpecificString("awsSessionToken")
	}
	region := cred.SpecificString("region")
	if region == "" {
		region = cred.SpecificString("awsRegion")
	}
	if akid == "" {
		akid = os.Getenv("AWS_ACCESS_KEY_ID")
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
		token = os.Getenv("AWS_SESSION_TOKEN")
	}
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1" // BEDROCK.defaultRegion
	}
	if !bedrockRegionRe.MatchString(region) {
		return awsCredentials{}, fmt.Errorf("bedrock: invalid AWS region %q", region)
	}
	if akid == "" || secret == "" {
		return awsCredentials{}, fmt.Errorf("bedrock: no AWS credentials resolved (static keys required in this port; profile/SSO resolution is TODO)")
	}
	return awsCredentials{AccessKeyID: akid, SecretAccessKey: secret, SessionToken: token, Region: region}, nil
}

// buildURL ports BedrockExecutor.buildUrl incl. the upfront model-family
// rejection (fail before the upstream call is billed).
func (e *BedrockExecutor) buildURL(p *ProviderInfo, model string, stream bool, region string) (string, error) {
	format := e.wireFormat(p)
	if pat, ok := bedrockFamilyPatterns[format]; ok && pat != nil {
		if !pat.MatchString(model) {
			return "", fmt.Errorf(
				"Bedrock model %q is not supported by the %s provider, which expects %s. Model families on Bedrock use different request and response shapes, so each gets its own provider entry rather than failing mid-stream after the call is billed.",
				model, e.providerID, bedrockFamilyHints[format])
		}
	}
	action := "invoke"
	if stream {
		action = "invoke-with-response-stream"
	}
	// Model id escaped once here; the signer escapes it again for the
	// canonical request, which Bedrock expects for ":0"-suffixed versions.
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/%s", region, escapeURI(model), action), nil
}

// transformBody ports transformRequest: both wires drop model/stream (model
// is in the URL, streaming is chosen by endpoint); only the Anthropic wire
// gets the version pin, applied after the spread so it overrides a
// client-carried anthropic_version.
func (e *BedrockExecutor) transformBody(p *ProviderInfo, body map[string]any) map[string]any {
	if body == nil {
		return map[string]any{}
	}
	out := cloneMap(body)
	delete(out, "model")
	delete(out, "stream")
	if e.wireFormat(p) == "claude" {
		out["anthropic_version"] = bedrockAnthropicVersion
	}
	return out
}

// Execute signs and sends the request, then unwraps the EventStream when
// streaming. Deliberately NO refresh path: SigV4 has no bearer token to
// refresh into chatCore's 401 retry (bedrock.js comment) — credentials are
// re-resolved on every request instead.
func (e *BedrockExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: e.providerID}
	}
	resolved, err := resolveAWSCredentials(cred)
	if err != nil {
		return nil, err
	}
	bodyMap, _ := decodeBody(body)
	model := ModelOf(bodyMap)
	stream := StreamRequested(bodyMap) || p.ForceStream

	url, err := e.buildURL(p, model, stream, resolved.Region)
	if err != nil {
		return nil, err
	}
	transformed := e.transformBody(p, bodyMap)
	payload, err := marshalJSON(transformed)
	if err != nil {
		return nil, err
	}

	accept := "application/json"
	if stream {
		accept = "application/vnd.amazon.eventstream"
	}
	reqCtx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(connectTimeout(p), cancel)
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		timer.Stop()
		cancel()
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", accept)
	signAWSRequest(httpReq, payload, resolved, "bedrock", time.Now())

	resp, err := HTTPClient.Do(httpReq)
	if err != nil {
		timer.Stop()
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	timer.Stop()
	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}

	headers := map[string]string{"Content-Type": "application/json", "Accept": accept}
	result := &ExecResult{Response: resp, URL: url, Headers: headers, TransformedBody: payload}
	if stream && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		pr, pw := io.Pipe()
		go func() {
			err := convertBedrockEventStream(resp.Body, pw)
			resp.Body.Close()
			_ = pw.CloseWithError(err)
		}()
		result.Response = &http.Response{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}},
			Body:       pr,
		}
		result.ResponseFormat = e.wireFormat(p)
	}
	return result, nil
}

// convertBedrockEventStream unwraps Bedrock chunk frames: each payload is
// {"bytes": "<base64>"} whose decoded bytes are one wire-format event JSON;
// re-emitted as SSE `event: <type>` + `data: <json>` (Anthropic style) for
// the claude wire, or bare `data:` for the openai wire (chat chunks carry
// their own object marker).
func convertBedrockEventStream(r io.Reader, w io.Writer) error {
	er := &eventStreamReader{r: r}
	for {
		frame, err := er.next()
		if err == io.EOF {
			_, werr := io.WriteString(w, "data: [DONE]\n\n")
			return werr
		}
		if err != nil {
			emitSSEError(w, "bedrock_eventstream_error", err.Error())
			return nil
		}
		msgType := frame.HeaderString(":message-type")
		if msgType == "error" || msgType == "exception" {
			msg := getStr(frame.Payload, "message")
			if msg == "" {
				msg = "Bedrock upstream sent an EventStream " + msgType
			}
			emitSSEError(w, "bedrock_upstream_error", msg)
			return nil
		}
		b64 := getStr(frame.Payload, "bytes")
		if b64 == "" {
			continue
		}
		inner, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		var probe map[string]any
		_ = unmarshalJSON(inner, &probe)
		typ := getStr(probe, "type")
		if strings.HasPrefix(getStr(probe, "object"), "chat.completion") || typ == "" {
			fmt.Fprintf(w, "data: %s\n\n", inner)
		} else {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, inner)
		}
	}
}
