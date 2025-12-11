'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { getScan } from '@/lib/api';
import { Scan, Finding } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { VulnerabilityFindingsTable, VulnerabilityFinding } from '@/components/ui/vulnerability-findings-table';

export default function ScanPage() {
  const { id } = useParams();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchScan = async () => {
      try {
        const data = await getScan(id as string);
        setScan(data);
        
        // Poll if still running
        if (data.status === 'running') {
          setTimeout(fetchScan, 2000); // Poll every 2 seconds
        }
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    };
    fetchScan();
  }, [id]);

  if (loading) return <div className="container p-8">Loading...</div>;
  if (!scan) return <div>Scan not found</div>;

  const getSeverityColor = (severity: string) => {
    const colors = {
      CRITICAL: 'destructive',
      HIGH: 'destructive',
      MEDIUM: 'default',
      LOW: 'secondary',
    };
    return colors[severity as keyof typeof colors] || 'default';
  };

  const convertFindingsToVulnerabilityFindings = (findings: Finding[]): VulnerabilityFinding[] => {
    return findings.map((finding, index) => ({
      id: index.toString(),
      number: (index + 1).toString().padStart(2, '0'),
      title: finding.vulnerability,
      severity: finding.severity.toLowerCase() as VulnerabilityFinding['severity'],
      cweId: finding.cwe_id,
      filePath: finding.file_path,
      lineNumber: parseInt(finding.line_number) || 0,
      description: `${finding.vulnerability} detected in ${finding.file_path}`,
      confidence: finding.taint_flow ? 95 : 75, // Higher confidence if taint flow is verified
      status: "new" as VulnerabilityFinding['status'],
      category: "security" as VulnerabilityFinding['category']
    }));
  };

  const handleStatusChange = (findingId: string, newStatus: VulnerabilityFinding['status']) => {
    // Handle status changes - could update backend here
    console.log(`Finding ${findingId} status changed to ${newStatus}`);
  };

  return (
    <div className="container mx-auto p-8">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">{scan.name}</h1>
          <p className="text-muted-foreground">{scan.repo_url}</p>
        </div>
        <Button variant="outline" onClick={() => router.push('/')}>New Scan</Button>
      </div>

      {scan.status === 'running' && (
        <Card className="mb-6 border-blue-200 bg-blue-50">
          <CardContent className="pt-6">
            <div className="text-center space-y-3">
              <div className="flex items-center justify-center gap-2">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                <span className="text-blue-800 font-medium">Scan in progress...</span>
              </div>
              <p className="text-sm text-blue-600">Processing your repository for security vulnerabilities</p>
            </div>
          </CardContent>
        </Card>
      )}

      {scan.status === 'failed' && (
        <Card className="mb-6 border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-red-800 font-medium">❌ Scan failed</p>
              <p className="text-sm text-red-600 mt-2">{scan.error || 'Unknown error occurred'}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {scan.status === 'completed' && scan.findings && (
        <>
          <div className="grid grid-cols-5 gap-4 mb-8">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{scan.stats.total}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-red-600">Critical</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">{scan.stats.critical}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-orange-600">High</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600">{scan.stats.high}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-yellow-600">Medium</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-yellow-600">{scan.stats.medium}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Low</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{scan.stats.low}</div>
              </CardContent>
            </Card>
          </div>

          <VulnerabilityFindingsTable
            title={`Security Findings (${scan.findings.length})`}
            findings={convertFindingsToVulnerabilityFindings(scan.findings)}
            onStatusChange={handleStatusChange}
            scanId={scan.id}
            className="mt-8"
          />
        </>
      )}

      {scan.status === 'completed' && (!scan.findings || scan.findings.length === 0) && (
        <Card className="mb-6 border-green-200 bg-green-50">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-green-800 font-medium">Scan completed successfully</p>
              <p className="text-sm text-green-600 mt-2">No security vulnerabilities found in this codebase</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
