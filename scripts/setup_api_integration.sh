#!/bin/bash
#
# SSH Guardian 2.0 - API Integration Setup Script
# Interactive guide to set up third-party threat intelligence APIs
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

# Functions
print_header() {
    echo -e "\n${BOLD}${BLUE}========================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Welcome message
clear
print_header "SSH Guardian 2.0 - API Integration Setup"

echo "This script will help you set up third-party threat intelligence APIs."
echo "All APIs offer FREE tiers perfect for SME deployments."
echo ""
print_info "You can skip any API and set it up later."
echo ""

# Check if .env exists
if [ ! -f "$ENV_FILE" ]; then
    print_error ".env file not found!"
    print_info "Creating .env from template..."
    cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"
    print_success ".env file created"
fi

# VirusTotal Setup
print_header "1/3: VirusTotal API Setup"

echo "VirusTotal checks IPs against 70+ security vendors."
echo -e "${BOLD}Free Tier:${NC} 250 requests/day, 4 requests/minute"
echo ""
print_info "Registration: https://www.virustotal.com/gui/join-us"
echo ""

read -p "Do you want to set up VirusTotal? (y/n): " setup_vt

if [[ "$setup_vt" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Steps:"
    echo "1. Visit: https://www.virustotal.com/gui/join-us"
    echo "2. Sign up with email or Google"
    echo "3. Click your profile icon → 'API Key'"
    echo "4. Copy your 64-character API key"
    echo ""
    read -p "Enter your VirusTotal API key (64 chars): " vt_key

    # Validate length
    if [ ${#vt_key} -eq 64 ]; then
        # Update .env file
        if grep -q "^VIRUSTOTAL_API_KEY=" "$ENV_FILE"; then
            sed -i "s|^VIRUSTOTAL_API_KEY=.*|VIRUSTOTAL_API_KEY=\"$vt_key\"|" "$ENV_FILE"
        else
            echo "VIRUSTOTAL_API_KEY=\"$vt_key\"" >> "$ENV_FILE"
        fi
        print_success "VirusTotal API key saved!"
    else
        print_error "Invalid key length: ${#vt_key} (expected 64)"
        print_warning "Skipping VirusTotal setup"
    fi
else
    print_info "Skipping VirusTotal setup"
fi

# AbuseIPDB Setup
print_header "2/3: AbuseIPDB API Setup"

echo "AbuseIPDB provides community-driven abuse reporting database."
echo -e "${BOLD}Free Tier:${NC} 1,000 requests/day, 60 requests/minute"
echo ""
print_info "Registration: https://www.abuseipdb.com/pricing"
echo ""

read -p "Do you want to set up AbuseIPDB? (y/n): " setup_abuse

if [[ "$setup_abuse" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Steps:"
    echo "1. Visit: https://www.abuseipdb.com/pricing"
    echo "2. Click 'Sign Up Free'"
    echo "3. Go to: https://www.abuseipdb.com/account/api"
    echo "4. Click 'Create Key'"
    echo "5. Copy your 80-character API key"
    echo ""
    read -p "Enter your AbuseIPDB API key (80 chars): " abuse_key

    # Validate length
    if [ ${#abuse_key} -eq 80 ]; then
        # Update .env file
        if grep -q "^ABUSEIPDB_API_KEY=" "$ENV_FILE"; then
            sed -i "s|^ABUSEIPDB_API_KEY=.*|ABUSEIPDB_API_KEY=\"$abuse_key\"|" "$ENV_FILE"
        else
            echo "ABUSEIPDB_API_KEY=\"$abuse_key\"" >> "$ENV_FILE"
        fi
        print_success "AbuseIPDB API key saved!"
    else
        print_error "Invalid key length: ${#abuse_key} (expected 80)"
        print_warning "Skipping AbuseIPDB setup"
    fi
else
    print_info "Skipping AbuseIPDB setup"
fi

# Shodan Setup
print_header "3/3: Shodan API Setup"

echo "Shodan discovers exposed services and vulnerabilities."
echo -e "${BOLD}Free Tier:${NC} 100 API credits/month (limited)"
echo ""
print_info "Registration: https://account.shodan.io/register"
echo ""
print_warning "Tip: Use Shodan sparingly for high-risk IPs only"
echo ""

read -p "Do you want to set up Shodan? (y/n): " setup_shodan

if [[ "$setup_shodan" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Steps:"
    echo "1. Visit: https://account.shodan.io/register"
    echo "2. Sign up and verify email"
    echo "3. Your API key is shown at top of account page"
    echo "4. Copy your 32-character API key"
    echo ""
    read -p "Enter your Shodan API key (32 chars): " shodan_key

    # Validate length
    if [ ${#shodan_key} -eq 32 ]; then
        # Update .env file
        if grep -q "^SHODAN_API_KEY=" "$ENV_FILE"; then
            sed -i "s|^SHODAN_API_KEY=.*|SHODAN_API_KEY=\"$shodan_key\"|" "$ENV_FILE"
        else
            echo "SHODAN_API_KEY=\"$shodan_key\"" >> "$ENV_FILE"
        fi
        print_success "Shodan API key saved!"
    else
        print_error "Invalid key length: ${#shodan_key} (expected 32)"
        print_warning "Skipping Shodan setup"
    fi
else
    print_info "Skipping Shodan setup"
fi

# Validation
print_header "Validating Configuration"

echo "Running validation script..."
echo ""

python3 "$PROJECT_ROOT/scripts/validate_api_keys.py"
validation_result=$?

# Testing
if [ $validation_result -eq 0 ]; then
    echo ""
    print_success "Configuration validated successfully!"
    echo ""
    read -p "Do you want to test API connectivity now? (y/n): " run_test

    if [[ "$run_test" =~ ^[Yy]$ ]]; then
        print_header "Testing API Integration"
        python3 "$PROJECT_ROOT/scripts/test_api_integration.py" --test-all
    fi
fi

# Summary
print_header "Setup Complete"

echo "Next steps:"
echo ""
print_info "1. Review your .env file: $ENV_FILE"
print_info "2. Read the full guide: docs/API_SETUP_GUIDE.md"
print_info "3. Restart SSH Guardian to use the new APIs"
echo ""
print_success "API integration setup finished!"
echo ""
