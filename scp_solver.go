package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SCPSolver struct {
	host        string
	user        string
	keyPath     string
	webrootPath string
	sshClient   *ssh.Client
}

func NewSCPSolver(host, user, keyPath, webrootPath string) *SCPSolver {
	return &SCPSolver{
		host:        host,
		user:        user,
		keyPath:     keyPath,
		webrootPath: webrootPath,
	}
}

func (s *SCPSolver) Present(domain, token, keyAuth string) error {
	// Connect to SSH
	if err := s.connect(); err != nil {
		return fmt.Errorf("SSH connection failed: %v", err)
	}
	defer s.sshClient.Close()

	// Create remote directory - fix double slash issue
	webrootPath := s.webrootPath
	if webrootPath[len(webrootPath)-1] == '/' {
		webrootPath = webrootPath[:len(webrootPath)-1]
	}
	remotePath := webrootPath + "/.well-known/acme-challenge"
	fmt.Printf("Creating remote directory: %s\n", remotePath)
	if err := s.createRemoteDir(remotePath); err != nil {
		return fmt.Errorf("failed to create remote directory: %v", err)
	}

	// Upload challenge file
	remoteFile := remotePath + "/" + token
	fmt.Printf("Uploading challenge file to: %s\n", remoteFile)
	fmt.Printf("Challenge content: %s\n", keyAuth)
	if err := s.uploadFile(remoteFile, keyAuth); err != nil {
		return fmt.Errorf("failed to upload challenge file: %v", err)
	}

	// Set proper permissions for web server access
	if err := s.setPermissions(remotePath, remoteFile); err != nil {
		fmt.Printf("Warning: Failed to set permissions: %v\n", err)
	}

	// Create .htaccess rule for .well-known access
	if err := s.createHtaccessRule(webrootPath); err != nil {
		fmt.Printf("Warning: Failed to create .htaccess rule: %v\n", err)
	}
	
	// Create nginx configuration for .well-known access
	if err := s.createNginxConfig(webrootPath, domain); err != nil {
		fmt.Printf("Warning: Failed to create nginx config: %v\n", err)
	}

	// Verify file was created
	if err := s.verifyFile(remoteFile); err != nil {
		return fmt.Errorf("failed to verify challenge file: %v", err)
	}

	// Test HTTP accessibility
	if err := s.testHTTPAccess(domain, token); err != nil {
		fmt.Printf("Warning: HTTP test failed: %v\n", err)
	}

	return nil
}

func (s *SCPSolver) CleanUp(domain, token, keyAuth string) error {
	if err := s.connect(); err != nil {
		return fmt.Errorf("SSH connection failed: %v", err)
	}
	defer s.sshClient.Close()

	// Remove challenge file - fix double slash issue
	webrootPath := s.webrootPath
	if webrootPath[len(webrootPath)-1] == '/' {
		webrootPath = webrootPath[:len(webrootPath)-1]
	}
	remoteFile := webrootPath + "/.well-known/acme-challenge/" + token
	fmt.Printf("Cleaning up file: %s\n", remoteFile)
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	return session.Run(fmt.Sprintf("rm -f %s", remoteFile))
}

func (s *SCPSolver) connect() error {
	key, err := os.ReadFile(s.keyPath)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	s.sshClient, err = ssh.Dial("tcp", s.host+":22", config)
	return err
}

func (s *SCPSolver) createRemoteDir(path string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	return session.Run(fmt.Sprintf("mkdir -p %s", path))
}

func (s *SCPSolver) uploadFile(remotePath, content string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// Use printf to avoid issues with special characters in content
	cmd := fmt.Sprintf("printf '%%s' '%s' > %s", content, remotePath)
	fmt.Printf("Executing command: %s\n", cmd)

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Printf("Command output: %s\n", string(output))
		return fmt.Errorf("command failed: %v, output: %s", err, string(output))
	}

	return nil
}

func (s *SCPSolver) verifyFile(remotePath string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	cmd := fmt.Sprintf("ls -la %s && cat %s", remotePath, remotePath)
	fmt.Printf("Verifying file with command: %s\n", cmd)
	
	output, err := session.CombinedOutput(cmd)
	fmt.Printf("Verification output: %s\n", string(output))
	
	if err != nil {
		return fmt.Errorf("verification failed: %v", err)
	}
	
	return nil
}

func (s *SCPSolver) setPermissions(remotePath, remoteFile string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// Set directory and file permissions for web server access
	cmd := fmt.Sprintf("chmod 755 %s && chmod 644 %s", remotePath, remoteFile)
	fmt.Printf("Setting permissions: %s\n", cmd)
	
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Printf("Permission command output: %s\n", string(output))
		return err
	}
	
	return nil
}

func (s *SCPSolver) createHtaccessRule(webrootPath string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// Create .htaccess in the main directory to exclude .well-known from redirects
	mainHtaccessPath := webrootPath + "/.htaccess"
	
	// First check if the file exists and read it
	checkCmd := fmt.Sprintf("if [ -f %s ]; then cat %s; fi", mainHtaccessPath, mainHtaccessPath)
	output, err := session.CombinedOutput(checkCmd)
	if err != nil {
		fmt.Printf("Error checking .htaccess: %v\n", err)
	}
	
	currentHtaccess := string(output)
	fmt.Printf("Current .htaccess content: %s\n", currentHtaccess)
	
	// Create a new session for the update
	session.Close()
	session, err = s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	
	// Add exception for .well-known if it doesn't exist
	if currentHtaccess != "" && !strings.Contains(currentHtaccess, ".well-known") {
		wellKnownRule := `
# Allow ACME challenge access without redirects
RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
`
		// Insert the rule after RewriteEngine On
		updatedHtaccess := strings.Replace(
			currentHtaccess, 
			"RewriteEngine On", 
			"RewriteEngine On"+wellKnownRule, 
			1)
		
		cmd := fmt.Sprintf("printf '%%s' '%s' > %s", updatedHtaccess, mainHtaccessPath)
		fmt.Printf("Updating main .htaccess with .well-known exception\n")
		
		output, err := session.CombinedOutput(cmd)
		if err != nil {
			fmt.Printf(".htaccess update output: %s\n", string(output))
			return err
		}
	}
	
	// Also create a specific .htaccess in the .well-known directory
	session.Close()
	session, err = s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	
	htaccessPath := webrootPath + "/.well-known/.htaccess"
	htaccessContent := `# Allow ACME challenge access without redirects
RewriteEngine Off
`
	
	cmd := fmt.Sprintf("printf '%%s' '%s' > %s", htaccessContent, htaccessPath)
	fmt.Printf("Creating .htaccess rule: %s\n", htaccessPath)
	
	output, err = session.CombinedOutput(cmd)
	if err != nil {
		fmt.Printf(".htaccess command output: %s\n", string(output))
		return err
	}
	
	return nil
}

func (s *SCPSolver) createNginxConfig(webrootPath string, domain string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// Create a custom nginx config file in the user's home directory
	nginxConfigPath := "/home/" + s.user + "/nginx_acme_config.conf"
	nginxContent := fmt.Sprintf(`# Custom nginx configuration for ACME challenge
location /.well-known/acme-challenge/ {
    alias %s/.well-known/acme-challenge/;
    try_files $uri =404;
    allow all;
}
`, webrootPath)
	
	cmd := fmt.Sprintf("printf '%%s' '%s' > %s", nginxContent, nginxConfigPath)
	fmt.Printf("Creating nginx config: %s\n", nginxConfigPath)
	
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Printf("Nginx config output: %s\n", string(output))
		return err
	}
	
	fmt.Printf("Nginx configuration created. You may need to manually include this file in your nginx configuration.\n")
	fmt.Printf("File path: %s\n", nginxConfigPath)
	fmt.Printf("Content:\n%s\n", nginxContent)
	
	return nil
}

func (s *SCPSolver) testHTTPAccess(domain, token string) error {
	url := fmt.Sprintf("https://%s/.well-known/acme-challenge/%s", domain, token)
	fmt.Printf("Testing HTTP access: %s\n", url)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	
	fmt.Printf("HTTP response status: %d\n", resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	
	return nil
}
