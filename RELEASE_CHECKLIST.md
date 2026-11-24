# Release Checklist

Use this checklist when preparing a new release of the SBOM Aggregator Maven Plugin.

## Pre-Release Verification

- [ ] All tests pass locally: `mvn clean verify`
- [ ] Integration tests pass: `mvn clean install -Prun-its`
- [ ] Code is properly formatted and follows conventions
- [ ] All changes are committed and pushed to `main` branch
- [ ] No uncommitted changes in working directory
- [ ] CHANGELOG.md is updated with release notes for the new version
- [ ] Version in `pom.xml` (the release workflow sets it from the tag, so a manual edit is optional)
- [ ] README.md examples reference the correct version
- [ ] `.github/ISSUE_TEMPLATE/bug_report.md` examples reference the correct version
- [ ] All documentation is up to date

## Release Preparation

- [ ] Optional: the release workflow sets the version from the tag (`versions:set`), so editing `pom.xml` by hand is not required
- [ ] Update CHANGELOG.md: Replace `[Unreleased]` section date with actual release date
- [ ] Commit version changes:
  ```bash
  git add pom.xml CHANGELOG.md
  git commit -m "chore: prepare release vX.Y.Z"
  ```
- [ ] Push changes: `git push origin main`

## Release Execution

- [ ] Create Git tag: `git tag -a vX.Y.Z -m "Release version X.Y.Z"`
- [ ] Push tag to trigger release workflow: `git push origin vX.Y.Z`
- [ ] Monitor GitHub Actions workflow at: https://github.com/patropia/sbom-aggregator-maven-plugin/actions
- [ ] Verify workflow completes successfully (build, test, sign, deploy)
- [ ] Wait for artifact to sync to Maven Central (typically 10-30 minutes)
- [ ] Verify artifact is available at: https://central.sonatype.com/artifact/nl.patropia.maven.plugin/sbom-aggregator-maven-plugin

## Post-Release

- [ ] Create GitHub Release:
  - Go to: https://github.com/patropia/sbom-aggregator-maven-plugin/releases/new
  - Select the tag: `vX.Y.Z`
  - Title: `Release X.Y.Z`
  - Copy release notes from CHANGELOG.md
  - Publish release
- [ ] Update `pom.xml` to next SNAPSHOT version: `X.Y.(Z+1)-SNAPSHOT`
- [ ] Add new `[Unreleased]` section to CHANGELOG.md
- [ ] Commit post-release changes:
  ```bash
  git add pom.xml CHANGELOG.md
  git commit -m "chore: prepare for next development iteration"
  git push origin main
  ```
- [ ] Branch hygiene: delete merged work branches (`swarmcommand/run-*`, `wip/*`)
  and close Dependabot PRs that were folded into the release. For 1.1.0 this is
  scripted in [`scripts/release-housekeeping.sh`](scripts/release-housekeeping.sh)
  (run it with push rights and an authenticated `gh` CLI).
- [ ] Announce release (optional):
  - Update project documentation
  - Notify stakeholders
  - Post on relevant channels

## Verification Steps

After release, verify the following:

- [ ] Artifact appears on Maven Central: https://central.sonatype.com/artifact/nl.patropia.maven.plugin/sbom-aggregator-maven-plugin/X.Y.Z
- [ ] POM file is correct on Maven Central
- [ ] Javadoc JAR is present
- [ ] Sources JAR is present
- [ ] GPG signatures are present (.asc files)
- [ ] GitHub Release is created with proper notes
- [ ] README badges show correct version

## Troubleshooting

### Release workflow fails

**Symptoms**: GitHub Actions workflow fails during release

**Solutions**:
- Check GitHub Actions logs for specific error messages
- Verify GPG credentials in GitHub Secrets:
  - `GPG_PRIVATE_KEY`: ASCII-armored private key (gpg --armor --export-secret-keys)
  - `GPG_PASSPHRASE`: Passphrase for the private key
- Verify Central Portal token credentials in GitHub Secrets:
  - `CENTRAL_TOKEN_USERNAME`: Central Portal user token username
  - `CENTRAL_TOKEN_PASSWORD`: Central Portal user token password
- Ensure version in `pom.xml` doesn't have `-SNAPSHOT` suffix
- Verify all tests pass before release

### Artifact not appearing on Maven Central

**Symptoms**: Release succeeds but artifact doesn't appear on Maven Central

**Solutions**:
- Wait 10-30 minutes for sync (can take up to 2 hours in rare cases)
- Check the deployment status at https://central.sonatype.com/publishing/deployments
- Verify `central-publishing-maven-plugin` configuration in `pom.xml`
- Check if `autoPublish` is set to `true`
- If `autoPublish` is `false`, publish the validated deployment manually:
  1. Login to https://central.sonatype.com/publishing/deployments
  2. Open the pending deployment
  3. Review the validation results and click "Publish"

### GPG signing fails

**Symptoms**: Build fails during GPG signing step

**Solutions**:
- Verify GPG key is properly configured
- Check GPG passphrase is correct
- Ensure `maven-gpg-plugin` configuration includes `--pinentry-mode loopback`
- Test GPG signing locally: `mvn clean verify -Prelease`

### Version conflicts

**Symptoms**: Maven reports version conflicts or duplicate artifacts

**Solutions**:
- Ensure you're not trying to release a version that already exists
- Check Maven Central for existing versions
- If needed, increment version number and retry

## Emergency Rollback

If a critical issue is discovered after release:

1. **Do not delete the release** - Maven Central releases are immutable
2. Create a hotfix:
   - Branch from the release tag: `git checkout -b hotfix/X.Y.(Z+1) vX.Y.Z`
   - Fix the issue
   - Follow the release process for version `X.Y.(Z+1)`
3. Update documentation to recommend the new version
4. Consider marking the problematic version as deprecated in release notes

## Notes

- Maven Central releases are **immutable** - you cannot delete or modify a released version
- Always test thoroughly before releasing
- Keep CHANGELOG.md up to date with all changes
- Use semantic versioning: MAJOR.MINOR.PATCH
  - MAJOR: Breaking changes
  - MINOR: New features (backward compatible)
  - PATCH: Bug fixes (backward compatible)
