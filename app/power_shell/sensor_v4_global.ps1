# Configuration Variables
$WebhookUrl   = ""
$InterfaceNum = "" # Tshark interface number
$SecretKey    = "" # API Key

while ($true) {
    # Capture TLS SNI handshakes for 30 seconds
    $traffic = & "tshark" -i $InterfaceNum -a duration:30 -Y "tls.handshake.type == 1" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
    
    if ($traffic) {
        # Process lines, filter out empty lines first
        $payload = $traffic | Where-Object { $_ -match "\S" } | ForEach-Object {
            $split = $_ -split "`t"
            [PSCustomObject]@{
                timestamp = $split[0]
                src_ip    = $split[1]
                dst_ip    = $split[2]
                domain    = $split[3]
            }
        } | Where-Object {
            # Filter out Loopback, Private Subnets, Multicast, Reserved, and Broadcast addresses
            $_.dst_ip -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|(22[4-9]|2[3-5][0-9]))"
        } | Group-Object src_ip, dst_ip, domain | ForEach-Object { 
            # Deduplicate data while preserving key order
            $g = $_.Name -split ', '
            $firstPacket = $_.Group[0]
            
            [PSCustomObject]@{ 
                src_ip    = $g[0]
                dst_ip    = $g[1] 
                domain    = $g[2]
                timestamp = $firstPacket.timestamp
            }
        }

        if ($payload) {
            $jsonPayload = ConvertTo-Json @($payload) -Depth 10
            
            # Pass the variable into the headers hashtable
            $headers = @{
                "X-API-KEY" = $SecretKey
            }
            
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType "application/json" -Headers $headers -Body $jsonPayload
        }
    }
    Start-Sleep -Seconds 2
}