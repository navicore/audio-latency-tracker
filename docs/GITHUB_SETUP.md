# GitHub Actions Setup

To enable automatic Docker Hub publishing, you need to configure the following GitHub secrets:

## Required Secrets

1. **DOCKER_HUB_USERNAME**
   - Your Docker Hub username
   - Example: `myusername`

2. **DOCKER_HUB_TOKEN**
   - Docker Hub access token (not your password!)
   - Create at: https://hub.docker.com/settings/security
   - Select "Read, Write, Delete" permissions

## Setting up Secrets

1. Go to your repository on GitHub
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Add each secret with the appropriate value

## Docker Hub Repository

Make sure to create the repository on Docker Hub first:

1. Log in to https://hub.docker.com
2. Click "Create Repository"
3. Name: `audio-latency-tracker`
4. Visibility: Public (or Private if you prefer)
5. Click "Create"

## Testing the Workflow

After setting up the secrets:

1. Push to main branch or create a tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. Check GitHub Actions tab for build status

3. Verify image on Docker Hub:
   ```bash
   docker pull YOUR_USERNAME/audio-latency-tracker:latest
   ```

## Troubleshooting

If the build fails:
- Check the Actions logs for errors
- Verify secrets are correctly set
- Ensure Docker Hub repository exists
- Check that the access token has correct permissions