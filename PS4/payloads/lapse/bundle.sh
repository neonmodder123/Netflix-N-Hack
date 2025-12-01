#!/bin/bash

# Bundle PS4 lapse payload
# Creates a single bundled JS file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Files in order (order matters)
FILES=(
    "config.js"
    "kernel_offset.js"
    "misc.js"
    "kernel.js"
    "threading.js"
    "binloader.js"
)

OUTPUT="$SCRIPT_DIR/lapse.js"

echo "Bundling PS4 lapse payload..."

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
done

echo "Created: $OUTPUT"

# Syntax check
if node --check "$OUTPUT" 2>&1; then
    echo "Syntax check: OK"
else
    echo "Syntax check: FAILED"
    exit 1
fi

echo "Done!"
