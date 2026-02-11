#!/bin/bash
# Script to inject metadata from project-metadata.json into spec files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
METADATA_FILE="${PROJECT_ROOT}/project-metadata.json"
SPEC_TEMPLATE="${PROJECT_ROOT}/templates/yum/template.spec"
DEBIAN_TEMPLATE="${PROJECT_ROOT}/templates/apt/debian"
DEBIAN_OUTPUT="${PROJECT_ROOT}/debian"
SERVICE_TEMPLATE="${PROJECT_ROOT}/templates/systemd/service.template"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq."
    exit 1
fi

# Check if metadata file exists
if [ ! -f "$METADATA_FILE" ]; then
    echo "Error: Metadata file not found: $METADATA_FILE"
    exit 1
fi

# Check if spec template exists
if [ ! -f "$SPEC_TEMPLATE" ]; then
    echo "Error: Spec template not found: $SPEC_TEMPLATE"
    exit 1
fi

# Extract values from JSON
PACKAGE_NAME=$(jq -r '.package.name' "$METADATA_FILE")
PACKAGE_SUMMARY=$(jq -r '.package.summary' "$METADATA_FILE")
PACKAGE_DESCRIPTION=$(jq -r '.package.description' "$METADATA_FILE")
PACKAGE_LICENSE=$(jq -r '.package.license' "$METADATA_FILE")
PACKAGE_URL=$(jq -r '.package.url' "$METADATA_FILE")
COMPONENT_NAME=$(jq -r '.package.component_name' "$METADATA_FILE")
ARCH_RPM=$(jq -r '.architecture.rpm' "$METADATA_FILE")
MAINTAINER_NAME=$(jq -r '.maintainer.name' "$METADATA_FILE")
MAINTAINER_EMAIL=$(jq -r '.maintainer.email' "$METADATA_FILE")

# Extract build information
# Get commit SHA from environment variable (GitLab CI) or git command
if [ -n "$CI_COMMIT_SHA" ]; then
    BUILD_COMMIT_SHA="$CI_COMMIT_SHA"
else
    BUILD_COMMIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
fi

# Get build timestamp (ISO 8601 format)
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Get formatted dates for changelogs
# RFC 2822 format for Debian changelog (e.g., "Mon, 18 Dec 2025 12:34:56 +0000")
BUILD_DATE_RFC2822=$(date -R)

# RPM changelog format (e.g., "Wed Dec 18 2025")
BUILD_DATE_RPM=$(date "+%a %b %d %Y")

# Set output file based on package name (output to project root)
SPEC_OUTPUT="${PROJECT_ROOT}/${PACKAGE_NAME}.spec"

echo "Injecting metadata into spec file..."
echo "  Package Name: $PACKAGE_NAME"
echo "  Component: $COMPONENT_NAME"
echo "  Summary: $PACKAGE_SUMMARY"
echo "  Output: $SPEC_OUTPUT"

# Read the template and replace placeholders
cp "$SPEC_TEMPLATE" "$SPEC_OUTPUT"

# Replace placeholders
sed -i "s|{{PACKAGE_NAME}}|$PACKAGE_NAME|g" "$SPEC_OUTPUT"
sed -i "s|{{PACKAGE_SUMMARY}}|$PACKAGE_SUMMARY|g" "$SPEC_OUTPUT"
sed -i "s|{{PACKAGE_DESCRIPTION}}|$PACKAGE_DESCRIPTION|g" "$SPEC_OUTPUT"
sed -i "s|{{PACKAGE_LICENSE}}|$PACKAGE_LICENSE|g" "$SPEC_OUTPUT"
sed -i "s|{{PACKAGE_URL}}|$PACKAGE_URL|g" "$SPEC_OUTPUT"
sed -i "s|{{COMPONENT_NAME}}|$COMPONENT_NAME|g" "$SPEC_OUTPUT"
sed -i "s|{{ARCH_RPM}}|$ARCH_RPM|g" "$SPEC_OUTPUT"
sed -i "s|{{MAINTAINER_NAME}}|$MAINTAINER_NAME|g" "$SPEC_OUTPUT"
sed -i "s|{{MAINTAINER_EMAIL}}|$MAINTAINER_EMAIL|g" "$SPEC_OUTPUT"
sed -i "s|{{BUILD_COMMIT_SHA}}|$BUILD_COMMIT_SHA|g" "$SPEC_OUTPUT"
sed -i "s|{{BUILD_TIMESTAMP}}|$BUILD_TIMESTAMP|g" "$SPEC_OUTPUT"
sed -i "s|{{BUILD_DATE_RPM}}|$BUILD_DATE_RPM|g" "$SPEC_OUTPUT"

echo "Generated spec file: $SPEC_OUTPUT"

# Process systemd service template
echo ""
echo "Generating systemd service file..."
SERVICE_OUTPUT="${PROJECT_ROOT}/flomation-${COMPONENT_NAME}.service"

if [ -f "$SERVICE_TEMPLATE" ]; then
    cp "$SERVICE_TEMPLATE" "$SERVICE_OUTPUT"

    # Replace placeholders in service file
    sed -i "s|{{PACKAGE_NAME}}|$PACKAGE_NAME|g" "$SERVICE_OUTPUT"
    sed -i "s|{{PACKAGE_SUMMARY}}|$PACKAGE_SUMMARY|g" "$SERVICE_OUTPUT"
    sed -i "s|{{COMPONENT_NAME}}|$COMPONENT_NAME|g" "$SERVICE_OUTPUT"

    echo "  Generated service file: $SERVICE_OUTPUT"
else
    echo "  Warning: Service template not found: $SERVICE_TEMPLATE"
fi

# Process Debian template
echo ""
echo "Injecting metadata into Debian package files..."

# Check if debian template exists
if [ -d "$DEBIAN_TEMPLATE" ]; then
    echo "  Copying debian template to project root..."
    # Remove existing debian directory if it exists
    rm -rf "$DEBIAN_OUTPUT"
    # Copy debian template recursively
    cp -r "$DEBIAN_TEMPLATE" "$DEBIAN_OUTPUT"

    echo "  Renaming package-specific files..."
    # Rename generic files to package-specific names
    if [ -f "$DEBIAN_OUTPUT/package.install" ]; then
        mv "$DEBIAN_OUTPUT/package.install" "$DEBIAN_OUTPUT/${PACKAGE_NAME}.install"
    fi
    if [ -f "$DEBIAN_OUTPUT/package.conffiles" ]; then
        mv "$DEBIAN_OUTPUT/package.conffiles" "$DEBIAN_OUTPUT/${PACKAGE_NAME}.conffiles"
    fi

    echo "  Replacing placeholders in debian files..."
    # Find all files in debian directory and replace placeholders
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{PACKAGE_NAME}}|$PACKAGE_NAME|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{PACKAGE_SUMMARY}}|$PACKAGE_SUMMARY|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{PACKAGE_DESCRIPTION}}|$PACKAGE_DESCRIPTION|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{PACKAGE_LICENSE}}|$PACKAGE_LICENSE|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{PACKAGE_URL}}|$PACKAGE_URL|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{COMPONENT_NAME}}|$COMPONENT_NAME|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{MAINTAINER_NAME}}|$MAINTAINER_NAME|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{MAINTAINER_EMAIL}}|$MAINTAINER_EMAIL|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{BUILD_COMMIT_SHA}}|$BUILD_COMMIT_SHA|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{BUILD_TIMESTAMP}}|$BUILD_TIMESTAMP|g" {} \;
    find "$DEBIAN_OUTPUT" -type f -exec sed -i "s|{{BUILD_DATE_RFC2822}}|$BUILD_DATE_RFC2822|g" {} \;

    echo "  Generated debian directory: $DEBIAN_OUTPUT"
else
    echo "  Warning: Debian template not found: $DEBIAN_TEMPLATE"
fi

echo ""
echo "Done!"
