import { useState, useCallback, useEffect } from "react";
import { SidebarProvider } from "@/components/ui/sidebar";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import ChatArea from "@/components/ChatArea";
import ReportModal from "@/components/ReportModal";
import { checkHealth } from "@/lib/api";

const Index = () => {
  const [pendingQuery,   setPendingQuery]   = useState<string | null>(null);
  const [isConnected,    setIsConnected]    = useState(false);
  const [showReport,     setShowReport]     = useState(false);

  useEffect(() => {
    checkHealth().then(setIsConnected);
    const id = setInterval(() => checkHealth().then(setIsConnected), 15_000);
    return () => clearInterval(id);
  }, []);

  const handleQuickFilter   = useCallback((query: string) => setPendingQuery(query), []);
  const handleQueryConsumed = useCallback(() => setPendingQuery(null), []);

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar onQuickFilter={handleQuickFilter} />
        <div className="flex-1 flex flex-col min-h-screen">
          <TopBar
            isConnected={isConnected}
            onGenerateReport={() => setShowReport(true)}
          />
          <ChatArea pendingQuery={pendingQuery} onQueryConsumed={handleQueryConsumed} />
        </div>
      </div>

      {showReport && <ReportModal onClose={() => setShowReport(false)} />}
    </SidebarProvider>
  );
};

export default Index;
