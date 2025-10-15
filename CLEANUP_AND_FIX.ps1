# PRODUCTION CLEANUP SCRIPT
# This script removes all dead code and fixes issues before deployment

Write-Host "======================================================================"
Write-Host "  PRODUCTION CLEANUP - Removing Dead Code"
Write-Host "======================================================================"
Write-Host ""

# Files to delete (confirmed dead code)
$filesToDelete = @(
    "test_runner.py",              # Imports non-existent enhanced_agent
    "migrate_db.py",               # Imports non-existent enhanced_agent
    "website_integration.py",      # Website integration removed per user request
    "whatsapp_integration.py",     # Not used
    "test_website_connection.py",  # Tests removed website integration
    "config.py",                   # Not imported anywhere
    "production_config.py",        # Not imported anywhere
    "comprehensive_test.py",       # Old test file (using OPENROUTER_API_KEY)
    "quick_test.py",               # Old test file (using OPENROUTER_API_KEY)
    "generate_agent.py"            # Template system not used
)

Write-Host "Files marked for deletion:" -ForegroundColor Yellow
Write-Host ""

$totalSize = 0
foreach ($file in $filesToDelete) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length
        $totalSize += $size
        $sizeKB = [math]::Round($size / 1KB, 2)
        Write-Host "  [X] $file ($sizeKB KB)" -ForegroundColor Red
    } else {
        Write-Host "  [!] $file (already deleted)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Total size to free: $([math]::Round($totalSize / 1KB, 2)) KB" -ForegroundColor Cyan
Write-Host ""

# Ask for confirmation
$confirmation = Read-Host "Do you want to delete these files? (yes/no)"

if ($confirmation -eq "yes") {
    Write-Host ""
    Write-Host "Deleting files..." -ForegroundColor Yellow
    Write-Host ""
    
    $deletedCount = 0
    foreach ($file in $filesToDelete) {
        if (Test-Path $file) {
            Remove-Item $file -Force
            Write-Host "  [OK] Deleted: $file" -ForegroundColor Green
            $deletedCount++
        }
    }
    
    Write-Host ""
    Write-Host "Cleanup complete! Deleted $deletedCount files" -ForegroundColor Green
    Write-Host ""
    
    # Show remaining Python files
    Write-Host "Remaining Python files (production code):" -ForegroundColor Cyan
    Write-Host ""
    
    $productionFiles = @(
        "agentic_ai.py",
        "api_server.py",
        "auth_system.py",
        "rag_system.py",
        "test_data.py",
        "load_env.py",
        "regression_test.py"
    )
    
    foreach ($file in $productionFiles) {
        if (Test-Path $file) {
            $size = (Get-Item $file).Length
            $sizeKB = [math]::Round($size / 1KB, 2)
            Write-Host "  [OK] $file ($sizeKB KB)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "Ready to commit changes!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Run these commands:" -ForegroundColor Yellow
    Write-Host "  git add ." -ForegroundColor White
    Write-Host "  git commit -m 'Production cleanup: Remove dead code and broken files'" -ForegroundColor White
    Write-Host "  git push" -ForegroundColor White
    Write-Host ""
    
} else {
    Write-Host ""
    Write-Host "Cleanup cancelled by user" -ForegroundColor Red
    Write-Host ""
}
