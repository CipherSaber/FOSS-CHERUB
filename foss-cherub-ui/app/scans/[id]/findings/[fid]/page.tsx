'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { getScan, getFindingMitigation } from '@/lib/api';
import { Finding } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CodeBlock, CodeBlockCode } from '@/components/ui/code-block';

export default function FindingDetailPage() {
  const { id, fid } = useParams();
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [mitigation, setMitigation] = useState<string>("");
  const [loadingMitigation, setLoadingMitigation] = useState(false);

  useEffect(() => {
    const fetchFinding = async () => {
      const scan = await getScan(id as string);
      setFinding(scan.findings[parseInt(fid as string)]);
    };
    fetchFinding();
  }, [id, fid]);

  const loadMitigation = async () => {
    if (!finding || mitigation) return;
    setLoadingMitigation(true);
    try {
      const result = await getFindingMitigation(id as string, parseInt(fid as string));
      setMitigation(result.mitigation);
    } catch (error) {
      setMitigation("Failed to load mitigation advice.");
    } finally {
      setLoadingMitigation(false);
    }
  };

  if (!finding) return <div>Loading...</div>;

  return (
    <div className="container mx-auto p-8">
      <Button variant="outline" onClick={() => router.back()} className="mb-6">
        ← Back to Results
      </Button>

      <div className="flex items-center gap-3 mb-6">
        <Badge variant="destructive" className="text-lg px-3 py-1">{finding.severity}</Badge>
        <h1 className="text-3xl font-bold">{finding.vulnerability}</h1>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-8">
        <Card>
          <CardHeader><CardTitle className="text-sm">File</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-sm">{finding.file_path}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Line</CardTitle></CardHeader>
          <CardContent><p className="text-2xl font-bold">{finding.line_number}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">CWE / CVE</CardTitle></CardHeader>
          <CardContent><p>{finding.cwe_id} / {finding.cve_id}</p></CardContent>
        </Card>
      </div>

      <Tabs defaultValue="code">
        <TabsList>
          <TabsTrigger value="code">Code</TabsTrigger>
          <TabsTrigger value="ast">AST Analysis</TabsTrigger>
          <TabsTrigger value="mitigation" onClick={loadMitigation}>AI Mitigation</TabsTrigger>
          <TabsTrigger value="taint">Taint Flow</TabsTrigger>
          <TabsTrigger value="cve">CVE Info</TabsTrigger>
        </TabsList>

        <TabsContent value="code">
          <Card>
            <CardHeader><CardTitle>Code Snippet</CardTitle></CardHeader>
            <CardContent>
              <CodeBlock>
                <CodeBlockCode 
                  code={finding.code_snippet} 
                  language={finding.primary_language?.toLowerCase() || 'text'}
                  theme="github-light"
                />
              </CodeBlock>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ast">
          <Card>
            <CardHeader><CardTitle>AST Analysis</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Language Detection</h4>
                  <Badge variant="outline">{finding.primary_language}</Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Vulnerability Pattern</h4>
                  <p className="text-sm bg-slate-100 p-3 rounded">{finding.vulnerability}</p>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Taint Analysis Confidence</h4>
                  <Badge variant={finding.taint_confidence === 'high' ? 'default' : 'secondary'}>
                    {finding.taint_confidence || 'medium'}
                  </Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Code Context</h4>
                  <p className="text-sm text-muted-foreground">
                    Line {finding.line_number} in {finding.file_path.split('/').pop()}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="mitigation">
          <Card>
            <CardHeader><CardTitle>AI-Powered Mitigation Advice</CardTitle></CardHeader>
            <CardContent>
              {loadingMitigation ? (
                <div className="flex items-center gap-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                  <span>Generating mitigation advice...</span>
                </div>
              ) : mitigation ? (
                <div className="prose max-w-none">
                  <pre className="bg-slate-50 p-4 rounded whitespace-pre-wrap text-sm">{mitigation}</pre>
                </div>
              ) : (
                <Button onClick={loadMitigation} variant="outline">
                  Generate Mitigation Advice
                </Button>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="taint">
          <Card>
            <CardHeader><CardTitle>Data Flow Analysis</CardTitle></CardHeader>
            <CardContent>
              {finding.taint_flow ? (
                <pre className="bg-slate-100 p-4 rounded whitespace-pre-wrap text-sm">{finding.taint_flow}</pre>
              ) : (
                <p className="text-muted-foreground">No taint flow data available</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cve">
          <Card>
            <CardHeader><CardTitle>CWE / CVE Details</CardTitle></CardHeader>
            <CardContent>
              <p><strong>CWE:</strong> {finding.cwe_id}</p>
              <p><strong>CVE:</strong> {finding.cve_id}</p>
              <p className="mt-4 text-sm text-muted-foreground">
                Link: <a href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                         target="_blank" className="text-blue-600 underline">
                  View on MITRE
                </a>
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
