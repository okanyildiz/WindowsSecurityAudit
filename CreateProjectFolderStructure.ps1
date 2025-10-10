# Create main project folder
New-Item -Path "C:\WindowsSecurityAudit" -ItemType Directory -Force

# Create subfolders
$folders = @(
    "C:\WindowsSecurityAudit\Core",
    "C:\WindowsSecurityAudit\Detection", 
    "C:\WindowsSecurityAudit\Analysis",
    "C:\WindowsSecurityAudit\Response",
    "C:\WindowsSecurityAudit\Enterprise",
    "C:\WindowsSecurityAudit\Hardening",
    "C:\WindowsSecurityAudit\WindowsDefender",
    "C:\WindowsSecurityAudit\Private",
    "C:\WindowsSecurityAudit\Tests",
	"C:\WindowsSecurityAudit\Reporting",
	"C:\WindowsSecurityAudit\CloudSecurity",
	"C:\WindowsSecurityAudit\Forensics",
	"C:\WindowsSecurityAudit\Vulnerability",
	"C:\WindowsSecurityAudit\Compliance",
	"C:\WindowsSecurityAudit\ThreatHunting",
	"C:\WindowsSecurityAudit\ActiveDirectory"
)

foreach ($folder in $folders) {
    New-Item -Path $folder -ItemType Directory -Force
}