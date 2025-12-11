"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan } from "@/lib/api";
import type { Scan, Finding } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  VulnerabilityFindingsTable,
  VulnerabilityFinding,
} from "@/components/ui/vulnerability-findings-table";

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

        // Poll while scan is running
        if (data.status === "running") {
          setTimeout(fetchScan, 3000);
        }
      } catch (error) {
        console.error("Failed to load scan", error);
      } finally {
        setLoading(false);
      }
    };

    fetchScan();
  }, [id]);

  if (loading) {
    return <div className="container p-8">Loading…</div>;
  }

  if (!scan) {
    return <div className="container p-8">Scan not found</div>;
  }

  const convertFindings = (findings: Finding[]): VulnerabilityFinding[] =>
    findings.map((finding, index) => ({
      id: index.toString(),
      number: (index + 1).toString().padStart(2, "0"),
      title: finding.vulnerability,
      severity: finding.severity.toLowerCase() as VulnerabilityFinding["severity"],
      cweId: finding.cwe_id,
      filePath: finding.file_path,
      lineNumber: parseInt(finding.line_number) || 0,
      description: `${finding.vulnerability} detected in ${finding.file_path}`,
      confidence: finding.taint_flow ? 95 : 75,
      status: "new",
      category: "security",
    }));

  const handleStatusChange = (
    findingId: string,
    newStatus: VulnerabilityFinding["status"],
  ) => {
    console.log(`Finding ${findingId} status changed to ${newStatus}`);
    // Optional: send status update to backend here
  };

  return (
    <div className="container mx-auto p-8 space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">{scan.name}</h1>
          <p className="text-sm text-muted-foreground">{scan.repo_url}</p>
        </div>
        <Button variant="outline" onClick={() => router.push("/")}>
          New scan
        </Button>
      </div>

      {/* Status banner */}
      {scan.status === "running" && (
        <Card>
          <CardContent className="pt-6 pb-6 text-center">
            <p>🔍 Scan in progress… This may take a few minutes.</p>
          </CardContent>
        </Card>
      )}

      {/* Metrics row (Streamlit-style) */}
      {scan.status === "completed" && scan.stats && (
        <div className="grid grid-cols-5 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Total findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{scan.stats.total}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-red-600">
                Critical
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {scan.stats.critical}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-orange-600">
                High
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">
                {scan.stats.high}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-yellow-600">
                Medium
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">
                {scan.stats.medium}
              </div>
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
      )}

      {/* Findings table */}
      {scan.status === "completed" && (
        <VulnerabilityFindingsTable
          title={`Security Findings (${scan.findings.length})`}
          findings={convertFindings(scan.findings)}
          onStatusChange={handleStatusChange}
          className="mt-4"
        />
      )}
    </div>
  );
}
