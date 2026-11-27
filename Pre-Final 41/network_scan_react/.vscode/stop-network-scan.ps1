$ports = @(5000, 5500)

foreach ($port in $ports) {

    $connections = Get-NetTCPConnection `
        -LocalPort $port `
        -State Listen `
        -ErrorAction SilentlyContinue

    $processIds = $connections |
        Select-Object -ExpandProperty OwningProcess -Unique

    foreach ($processId in $processIds) {

        if ($processId -and $processId -ne 0) {

            Write-Host "Stopping process $processId on port $port"

            Stop-Process `
                -Id $processId `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ""
Write-Host "Network Scan Project servers stopped."