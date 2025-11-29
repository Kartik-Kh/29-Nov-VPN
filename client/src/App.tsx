import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { ApiStatusIndicator } from "@/components/api-status-indicator";
import { Button } from "@/components/ui/button";
import Dashboard from "@/pages/dashboard";
import NotFound from "@/pages/not-found";
import { Shield, Plus } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

function Header() {
  const { data: healthData, isError } = useQuery({
    queryKey: ["/api/health"],
    refetchInterval: 30000,
  });

  const isConnected = !isError && healthData?.status === "ok";

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <div className="hidden sm:block">
              <h1 className="text-lg font-semibold tracking-tight">
                Proxy & VPN Detector
              </h1>
              <p className="text-xs text-muted-foreground -mt-0.5">
                Security Bureau
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <ApiStatusIndicator isConnected={isConnected} />
            <Button
              size="default"
              onClick={() => {
                const input = document.querySelector<HTMLInputElement>('[data-testid="input-ip-address"]');
                if (input) {
                  input.focus();
                  input.scrollIntoView({ behavior: "smooth", block: "center" });
                }
              }}
              data-testid="button-new-analysis"
            >
              <Plus className="h-4 w-4 mr-2" />
              New Analysis
            </Button>
            <ThemeToggle />
          </div>
        </div>
      </div>
    </header>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="vpn-detector-theme">
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <div className="min-h-screen bg-background">
            <Header />
            <main>
              <Router />
            </main>
          </div>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
