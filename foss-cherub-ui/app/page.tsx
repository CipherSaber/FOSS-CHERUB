"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import TetrisLoading from "@/components/ui/tetris-loader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FlickeringGrid } from "@/components/ui/flickering-grid";
import { createScan, uploadScan, checkApiHealth, getScan } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();

  const [isScanning, setIsScanning] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string>("");
  const [estimatedTime, setEstimatedTime] = useState<string>("3-5 minutes");
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);

  // Check API health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        await checkApiHealth();
        setApiError(null);
        console.log("✓ API is healthy");
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        setApiError(errorMsg);
        console.error("✗ API health check failed:", errorMsg);
      }
    };

    checkHealth();
  }, []);

  const handleStartScan = async () => {
    if (!repoUrl && !file) return;

    try {
      await checkApiHealth();
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      setApiError(errorMsg);
      alert("Cannot reach API server. Make sure the backend is running on port 8082.");
      return;
    }

    setIsScanning(true);
    setScanStatus("Initializing scan...");
    setScanStartTime(Date.now());
    setEstimatedTime("3-5 minutes");
    
    try {
      let scan: { scan_id?: string } | undefined;

      if (file) {
        scan = await uploadScan(file);
      } else {
        scan = await createScan(repoUrl, "New Scan");
      }

      if (scan?.scan_id) {
        setScanId(scan.scan_id);
        pollScanStatus(scan.scan_id);
      } else {
        throw new Error("No scan ID returned");
      }
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      setApiError(errorMsg);
      console.error(e);
      setIsScanning(false);
    }
  };

  const pollScanStatus = async (scanId: string) => {
    try {
      const scanData = await getScan(scanId);
      
      if (scanData.status === "running") {
        setScanStatus("...Running the scanners...");
        
        // Update estimated time based on elapsed time
        if (scanStartTime) {
          const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
          if (elapsed < 60) {
            setEstimatedTime("3-5 minutes");
          } else if (elapsed < 120) {
            setEstimatedTime("2-3 minutes");
          } else if (elapsed < 180) {
            setEstimatedTime("1-2 minutes");
          } else {
            setEstimatedTime("Almost done");
          }
        }
        
        setTimeout(() => pollScanStatus(scanId), 2000);
      } else if (scanData.status === "completed") {
        setScanStatus("Analysis complete");
        setTimeout(() => {
          router.push(`/scans/${scanId}`);
        }, 1000);
      } else if (scanData.status === "failed") {
        setApiError("Scan failed: " + (scanData.error || "Unknown error"));
        setIsScanning(false);
      }
    } catch (error) {
      console.error("Error polling scan status:", error);
      setTimeout(() => pollScanStatus(scanId), 3000);
    }
  };



  return (
    <div className="relative min-h-screen flex items-center justify-center bg-white overflow-hidden">
      <FlickeringGrid
        className="absolute inset-0 z-0"
        squareSize={4}
        gridGap={6}
        color="#10b981"
        maxOpacity={0.3}
        flickerChance={0.1}
      />
      <div className="relative z-10 grid gap-10 md:grid-cols-2 w-full max-w-5xl p-6 md:p-10">
        {/* Left: hero copy + form */}
        <div className="flex flex-col justify-center space-y-6">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-emerald-600 mb-2">
              Qwen Coder + Semgrep + AST
            </p>
            <h1 className="text-4xl md:text-5xl font-semibold text-slate-900 relative z-20">
              FOSS‑CHERUB
              <span className="block text-slate-600 text-xl md:text-2xl mt-2">
                Multi‑language vulnerability scanner
              </span>
            </h1>
          </div>

          {/* Error Banner */}
          {apiError && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-sm text-red-800 font-mono">{apiError}</p>
            </div>
          )}

          {/* Input form */}
          <div className="space-y-3">
            <label className="block text-xs font-mono text-slate-600 relative z-20">
              GITHUB REPOSITORY URL
            </label>
            <Input
              placeholder="https://github.com/username/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={isScanning}
            />

            <div className="flex items-center gap-3">
              <span className="text-[10px] font-mono text-slate-700 relative z-20">
                OR UPLOAD ARCHIVE
              </span>
              <Input
                type="file"
                accept=".zip,.tar,.tar.gz"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                disabled={isScanning}
                className="text-xs"
              />
            </div>

            <Button
              variant="outline"
              className="mt-4 w-full md:w-auto"
              onClick={handleStartScan}
              disabled={isScanning || (!repoUrl && !file)}
            >
              {isScanning ? "Scanning…" : "Start Scan"}
            </Button>
          </div>
        </div>

        {/* Right: scanner status */}
        <div className="flex flex-col items-center justify-center space-y-6">
          {isScanning ? (
            <div className="text-center space-y-6">
              <TetrisLoading 
                size="md" 
                speed="normal" 
                showLoadingText={false}
              />
              
              <div className="space-y-3 max-w-sm">
                <div className="flex items-center justify-center gap-2">
                  <span className="text-emerald-800 font-semibold">Scanning in progress...</span>
                </div>
                
                <p className="text-sm text-slate-600 font-mono uppercase tracking-[0.3em]">
                  {scanStatus}
                </p>
                
                <p className="text-xs text-slate-500 font-mono uppercase tracking-[0.3em] mt-3">
                  Estimated time: {estimatedTime}
                </p>
              </div>
            </div>
          ) : (
            <div className="text-center text-slate-400 relative z-20">
              <p className="font-mono text-sm">Ready to scan</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}