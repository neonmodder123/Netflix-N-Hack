#!/bin/bash

# Bundle PS4 lapse payload
# Creates a single bundled JS file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ask user which payload
echo "Select payload:"
echo "  1) Jailbreak only (lapse.js)"
echo "  2) Jailbreak + BinLoader (lapse_binloader.js)"
read -p "Choice [1-2]: " choice

# Base files (always included)
FILES=(
    "config.js"
    "kernel_offset.js"
    "misc.js"
    "kernel.js"
    "threading.js"
    "lapse_stages.js"
)

# Main execution
FILES+=("lapse_main.js")

# Add payload after main if requested
case "$choice" in
    2)
        FILES+=("binloader.js")
        OUTPUT="$SCRIPT_DIR/lapse_binloader.js"
        echo "Bundling with binloader payload..."
        ;;
    *)
        OUTPUT="$SCRIPT_DIR/lapse.js"
        echo "Bundling jailbreak only..."
        ;;
esac

# Clear/create output file
> "$OUTPUT"

# Add files
for file in "${FILES[@]}"; do
    filepath="$SCRIPT_DIR/$file"

    if [[ ! -f "$filepath" ]]; then
        echo "ERROR: Missing file: $filepath"
        exit 1
    fi

    echo "" >> "$OUTPUT"
    echo "/***** $file *****/" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    cat "$filepath" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    echo "  Added: $file"
done

echo ""
echo "Created: $OUTPUT"

# Syntax check
if node --check "$OUTPUT" 2>&1; then
    echo "Syntax check: OK"
else
    echo "Syntax check: FAILED"
    exit 1
fi

echo "Done!"
