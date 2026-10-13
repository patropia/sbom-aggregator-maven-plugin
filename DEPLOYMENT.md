# Deployment Guide

This guide explains how to deploy the SBOM Aggregator Maven Plugin to Maven Central.

## Prerequisites

1. **Sonatype OSSRH Account**
   - Create an account at https://issues.sonatype.org/
   - Create a JIRA ticket to claim the `nl.patropia` groupId
   - Wait for approval (usually 1-2 business days)

2. **GPG Key for Signing**
   ```bash
   # Generate a GPG key
   gpg --gen-key
   
   # List keys to get the key ID
   gpg --list-keys
   
   # Export the public key to a keyserver
   gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
   
   # Export private key for GitHub Actions
   gpg --export-secret-keys YOUR_KEY_ID | base64
   ```

3. **GitHub Secrets**
   
   Configure the following secrets in your GitHub repository (Settings → Secrets and variables → Actions):
   
   - `OSSRH_USERNAME`: Your Sonatype JIRA username
   - `OSSRH_TOKEN`: Your Sonatype JIRA password or token
   - `GPG_PRIVATE_KEY`: Base64-encoded GPG private key
   - `GPG_PASSPHRASE`: Passphrase for your GPG key

## Release Process

### 1. Prepare the Release

Update version numbers and ensure all tests pass:

```bash
# Run all tests
mvn clean verify -Prun-its

# Update CHANGELOG.md with release notes
# Update version in README.md examples
```

### 2. Create and Push a Release Tag

```bash
# Create a tag for the release
git tag -a v1.0.0 -m "Release version 1.0.0"

# Push the tag to GitHub
git push origin v1.0.0
```

### 3. Automated Deployment

The GitHub Actions workflow will automatically:
1. Build and test the project
2. Sign artifacts with GPG
3. Deploy to Maven Central staging repository
4. Automatically release to Maven Central
5. Create a GitHub release with release notes

### 4. Verify Deployment

After the workflow completes:

1. Check Maven Central (may take 10-30 minutes to sync):
   - https://search.maven.org/search?q=g:nl.patropia.maven.plugin

2. Verify the GitHub release:
   - https://github.com/patropia/sbom-aggregator-maven-plugin/releases

## Manual Deployment (Alternative)

If you need to deploy manually:

### 1. Configure Maven Settings

Create or update `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>ossrh</id>
      <username>YOUR_SONATYPE_USERNAME</username>
      <password>YOUR_SONATYPE_PASSWORD</password>
    </server>
  </servers>
  
  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>YOUR_GPG_PASSPHRASE</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

### 2. Deploy to Maven Central

```bash
# Update version to release version
mvn versions:set -DnewVersion=1.0.0

# Deploy to Maven Central
mvn clean deploy -P release

# If auto-release is disabled, manually release via Nexus UI:
# https://s01.oss.sonatype.org/
```

### 3. Create GitHub Release

```bash
# Create and push tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0

# Create release via GitHub UI or CLI
gh release create v1.0.0 --title "Release 1.0.0" --notes "See CHANGELOG.md"
```

## Post-Release

1. **Update to Next Development Version**
   ```bash
   mvn versions:set -DnewVersion=1.1.0-SNAPSHOT
   git add pom.xml
   git commit -m "chore: bump version to 1.1.0-SNAPSHOT"
   git push origin main
   ```

2. **Announce the Release**
   - Update project website/documentation
   - Post on social media or relevant forums
   - Notify users via mailing list or discussions

3. **Monitor Issues**
   - Watch for bug reports or questions
   - Respond to GitHub issues promptly

## Troubleshooting

### GPG Signing Fails

```bash
# Ensure GPG agent is running
gpgconf --kill gpg-agent
gpgconf --launch gpg-agent

# Test signing
echo "test" | gpg --clearsign
```

### Deployment Hangs

- Check Nexus staging repository status: https://s01.oss.sonatype.org/
- Look for validation errors in the staging repository
- Ensure all required metadata is present (POM, sources, javadoc)

### Maven Central Sync Delay

- Initial sync can take 10-30 minutes
- Full propagation to all mirrors can take 2-4 hours
- Check status: https://repo1.maven.org/maven2/nl/patropia/maven/plugin/sbom-aggregator-maven-plugin/

## Resources

- [Sonatype OSSRH Guide](https://central.sonatype.org/publish/publish-guide/)
- [Maven GPG Plugin](https://maven.apache.org/plugins/maven-gpg-plugin/)
- [Nexus Staging Plugin](https://github.com/sonatype/nexus-maven-plugins/tree/main/staging/maven-plugin)
