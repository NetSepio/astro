package operations

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

// VideoTranscodingRequest represents the request body for video transcoding
type VideoTranscodingRequest struct {
	Format     string `json:"format" binding:"required"`     // Output format (e.g., "mp4", "webm", "avi")
	Resolution string `json:"resolution" binding:"required"` // Output resolution (e.g., "720p", "1080p")
}

// VideoTranscodingResponse represents the response for video transcoding
type VideoTranscodingResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	OutputPath  string `json:"outputPath,omitempty"`
	Duration    string `json:"duration,omitempty"`
	FileSize    int64  `json:"fileSize,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// ApplyRoutes applies the video transcoding routes to the router
func ApplyRoutes(r *gin.RouterGroup) {
	video := r.Group("/operations")
	{
		video.GET("/transcode", GetTranscodeForm)
		video.POST("/transcode", TranscodeVideo)
	}
}

// getContentType returns the appropriate content type for the given format
func getContentType(format string) string {
	switch format {
	case "mp4":
		return "video/mp4"
	case "webm":
		return "video/webm"
	case "avi":
		return "video/x-msvideo"
	default:
		return "video/mp4"
	}
}

// getFFmpegCodec returns the appropriate codec settings for the given format
func getFFmpegCodec(format string) (videoCodec, audioCodec string) {
	switch format {
	case "mp4":
		return "libx264", "aac"
	case "webm":
		return "libvpx-vp9", "libopus"
	case "avi":
		return "mpeg4", "mp3"
	default:
		return "libx264", "aac"
	}
}

// GetTranscodeForm serves the HTML form for video transcoding
func GetTranscodeForm(c *gin.Context) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Video Transcoding</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        select, input[type="file"] { width: 100%; padding: 8px; margin-bottom: 10px; }
        button { padding: 10px 20px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <h2>Video Transcoding</h2>
    <form action="/api/v1.0/operations/transcode" method="post" enctype="multipart/form-data">
        <div class="form-group">
            <label for="video">Select Video File:</label>
            <input type="file" id="video" name="video" accept="video/*" required>
        </div>
        <div class="form-group">
            <label for="format">Output Format:</label>
            <select id="format" name="data" required>
                <option value='{"format": "mp4", "resolution": "720p"}'>MP4 (720p)</option>
                <option value='{"format": "mp4", "resolution": "1080p"}'>MP4 (1080p)</option>
                <option value='{"format": "webm", "resolution": "720p"}'>WebM (720p)</option>
                <option value='{"format": "webm", "resolution": "1080p"}'>WebM (1080p)</option>
                <option value='{"format": "avi", "resolution": "720p"}'>AVI (720p)</option>
                <option value='{"format": "avi", "resolution": "1080p"}'>AVI (1080p)</option>
            </select>
        </div>
        <button type="submit">Transcode Video</button>
    </form>
</body>
</html>
`
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

// TranscodeVideo handles video file upload and transcoding using Docker
func TranscodeVideo(c *gin.Context) {
	log.Printf("[VideoTranscode] Starting video transcoding process")
	
	// Create temporary directories for input and output
	tempDir := filepath.Join(os.TempDir(), "video-transcoding")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[VideoTranscode] Error creating temp directory: %v", err)
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to create temporary directory",
		})
		return
	}
	log.Printf("[VideoTranscode] Created temp directory: %s", tempDir)

	// Get the uploaded file
	file, err := c.FormFile("video")
	if err != nil {
		log.Printf("[VideoTranscode] Error getting uploaded file: %v", err)
		c.JSON(http.StatusBadRequest, VideoTranscodingResponse{
			Success: false,
			Message: "No video file provided",
		})
		return
	}
	log.Printf("[VideoTranscode] Received file: %s, size: %d", file.Filename, file.Size)

	// Parse transcoding parameters
	var req VideoTranscodingRequest
	
	// Try to get parameters from form-data first
	if data := c.PostForm("data"); data != "" {
		log.Printf("[VideoTranscode] Received form-data: %s", data)
		if err := json.Unmarshal([]byte(data), &req); err != nil {
			log.Printf("[VideoTranscode] Error parsing JSON from form-data: %v", err)
			c.JSON(http.StatusBadRequest, VideoTranscodingResponse{
				Success: false,
				Message: "Invalid JSON in form-data: " + err.Error(),
			})
			return
		}
	} else {
		// If not in form-data, try to bind from JSON body
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[VideoTranscode] Error binding JSON body: %v", err)
			c.JSON(http.StatusBadRequest, VideoTranscodingResponse{
				Success: false,
				Message: "Invalid request parameters",
			})
			return
		}
	}
	log.Printf("[VideoTranscode] Parsed request - Format: %s, Resolution: %s", req.Format, req.Resolution)

	// Validate format
	validFormats := map[string]bool{
		"mp4":  true,
		"webm": true,
		"avi":  true,
	}
	if !validFormats[req.Format] {
		log.Printf("[VideoTranscode] Invalid format requested: %s", req.Format)
		c.JSON(http.StatusBadRequest, VideoTranscodingResponse{
			Success: false,
			Message: "Invalid format. Supported formats: mp4, webm, avi",
		})
		return
	}

	// Create input file path
	inputPath := filepath.Join(tempDir, fmt.Sprintf("input_%d%s", time.Now().Unix(), filepath.Ext(file.Filename)))
	if err := c.SaveUploadedFile(file, inputPath); err != nil {
		log.Printf("[VideoTranscode] Error saving uploaded file: %v", err)
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to save uploaded file",
		})
		return
	}
	log.Printf("[VideoTranscode] Saved input file to: %s", inputPath)

	// Create output file path
	outputPath := filepath.Join(tempDir, fmt.Sprintf("output_%d.%s", time.Now().Unix(), req.Format))
	outputDir := filepath.Dir(outputPath)
	outputFileName := filepath.Base(outputPath)
	log.Printf("[VideoTranscode] Output will be saved to: %s", outputPath)

	// Set resolution based on request
	var resolution string
	switch req.Resolution {
	case "720p":
		resolution = "1280x720"
	case "1080p":
		resolution = "1920x1080"
	default:
		resolution = "1280x720" // Default to 720p
	}
	log.Printf("[VideoTranscode] Using resolution: %s", resolution)

	// Get codec settings
	videoCodec, audioCodec := getFFmpegCodec(req.Format)
	log.Printf("[VideoTranscode] Using codecs - Video: %s, Audio: %s", videoCodec, audioCodec)

	// Pull FFmpeg image if not exists
	log.Printf("[VideoTranscode] Pulling FFmpeg Docker image...")
	pullCmd := exec.Command("docker", "pull", "jrottenberg/ffmpeg:latest")
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		log.Printf("[VideoTranscode] Error pulling FFmpeg image: %v\nOutput: %s", err, string(pullOutput))
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to pull FFmpeg image: " + err.Error(),
		})
		return
	}
	log.Printf("[VideoTranscode] Successfully pulled FFmpeg image")

	// Run FFmpeg container
	log.Printf("[VideoTranscode] Starting FFmpeg container...")
	runCmd := exec.Command("docker", "run", "--rm",
		"-v", fmt.Sprintf("%s:/input%s", inputPath, filepath.Ext(file.Filename)),
		"-v", fmt.Sprintf("%s:/output", outputDir),
		"jrottenberg/ffmpeg:latest",
		"-y", // Automatically overwrite output file
		"-i", "/input"+filepath.Ext(file.Filename),
		"-vf", fmt.Sprintf("scale=%s", resolution),
		"-c:v", videoCodec,
		"-q:v", "2", // Quality setting for MPEG4 (lower is better, range 1-31)
		"-c:a", audioCodec,
		"-b:a", "128k",
		"/output/"+outputFileName,
	)

	runOutput, err := runCmd.CombinedOutput()
	if err != nil {
		log.Printf("[VideoTranscode] Error running FFmpeg container: %v\nOutput: %s", err, string(runOutput))
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to transcode video: " + err.Error(),
		})
		return
	}
	log.Printf("[VideoTranscode] FFmpeg container output: %s", string(runOutput))

	// Get output file info
	outputFile, err := os.Open(outputPath)
	if err != nil {
		log.Printf("[VideoTranscode] Error opening output file: %v", err)
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to read output file",
		})
		return
	}
	defer outputFile.Close()

	fileInfo, err := outputFile.Stat()
	if err != nil {
		log.Printf("[VideoTranscode] Error getting output file info: %v", err)
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to get output file info",
		})
		return
	}
	log.Printf("[VideoTranscode] Output file size: %d bytes", fileInfo.Size())

	// Set content type based on output format
	contentType := getContentType(req.Format)
	log.Printf("[VideoTranscode] Setting content type: %s", contentType)

	// Set response headers
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=transcoded.%s", req.Format))
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Stream the transcoded video
	_, err = io.Copy(c.Writer, outputFile)
	if err != nil {
		log.Printf("[VideoTranscode] Error streaming video: %v", err)
		c.JSON(http.StatusInternalServerError, VideoTranscodingResponse{
			Success: false,
			Message: "Failed to stream video",
		})
		return
	}

	// Clean up temporary files
	defer os.Remove(inputPath)
	defer os.Remove(outputPath)
	log.Printf("[VideoTranscode] Cleaned up temporary files")

	// Don't send JSON response, we've already streamed the video
	return
}
