import { Shield, Wifi, WifiOff, User, FileText } from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";

interface TopBarProps {
  isConnected: boolean;
  onGenerateReport: () => void;
}

const TopBar = ({ isConnected, onGenerateReport }: TopBarProps) => {
  return (
    <header className="h-14 flex items-center justify-between px-4 border-b border-border bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <SidebarTrigger className="text-muted-foreground hover:text-foreground" />
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold font-mono tracking-tight text-foreground">
            Omni<span className="text-primary text-glow-primary">Log</span>
          </h1>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Generate Report button */}
        <button
          onClick={onGenerateReport}
          className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border border-primary/30 text-primary/80 bg-primary/5 hover:bg-primary/15 hover:text-primary hover:border-primary/60 transition-all"
        >
          <FileText className="h-3.5 w-3.5" />
          Generate Report
        </button>

        {/* Connection status */}
        <div className="flex items-center gap-2 text-sm">
          {isConnected ? (
            <>
              <Wifi className="h-4 w-4 text-accent" />
              <span className="text-accent font-mono text-xs">CONNECTED</span>
            </>
          ) : (
            <>
              <WifiOff className="h-4 w-4 text-destructive" />
              <span className="text-destructive font-mono text-xs">DISCONNECTED</span>
            </>
          )}
        </div>

        <div className="h-8 w-8 rounded-full bg-secondary flex items-center justify-center border border-border">
          <User className="h-4 w-4 text-muted-foreground" />
        </div>
      </div>
    </header>
  );
};

export default TopBar;
