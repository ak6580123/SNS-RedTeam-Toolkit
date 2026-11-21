<#
    Generates packaging/assets/icon.ico and logo.png (lemon badge) with System.Drawing.
    Run once; outputs are committed so normal builds don't need to run it.
    Replace the two files with your own artwork at any time.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot 'assets'
New-Item -ItemType Directory -Force $out | Out-Null

function New-Badge([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([System.Drawing.Color]::Transparent)
    $pad = [int]($size * 0.04); $d = $size - 2 * $pad
    # rounded dark tile
    $r = [int]($size * 0.22)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($pad, $pad, $r, $r, 180, 90); $path.AddArc($pad + $d - $r, $pad, $r, $r, 270, 90)
    $path.AddArc($pad + $d - $r, $pad + $d - $r, $r, $r, 0, 90); $path.AddArc($pad, $pad + $d - $r, $r, $r, 90, 90)
    $path.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 22, 24, 31))), $path)
    # lemon disc
    $m = [int]($size * 0.18)
    $rect = New-Object System.Drawing.Rectangle $m, $m, ($size - 2 * $m), ($size - 2 * $m)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, ([System.Drawing.Color]::FromArgb(255, 255, 233, 92)), ([System.Drawing.Color]::FromArgb(255, 240, 180, 20)), 45
    $g.FillEllipse($grad, $rect)
    # letter S
    $fs = [single]($size * 0.46)
    $font = New-Object System.Drawing.Font 'Segoe UI', $fs, ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
    $g.DrawString('S', $font, (New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 22, 24, 31))), (New-Object System.Drawing.RectangleF 0, ([single]($size * 0.02)), $size, $size), $sf)
    $g.Dispose()
    return $bmp
}

function Get-PngBytes($bmp) { $ms = New-Object System.IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); return ,$ms.ToArray() }

# logo.png
(New-Badge 256).Save((Join-Path $out 'logo.png'), [System.Drawing.Imaging.ImageFormat]::Png)

# icon.ico (PNG-compressed frames)
$sizes = 16, 24, 32, 48, 64, 128, 256
$frames = foreach ($s in $sizes) { ,(Get-PngBytes (New-Badge $s)) }
$fs = [System.IO.File]::Create((Join-Path $out 'icon.ico')); $bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $b = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$b); $bw.Write([byte]$b); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$frames[$i].Length); $bw.Write([uint32]$offset)
    $offset += $frames[$i].Length
}
foreach ($f in $frames) { $bw.Write($f) }
$bw.Close(); $fs.Close()
Write-Host "Wrote $out\icon.ico and logo.png"
