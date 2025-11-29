import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Search, Loader2, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { isValidIpAddress, getIpVersion } from "@shared/schema";

const ipFormSchema = z.object({
  ipAddress: z
    .string()
    .min(1, "IP address is required")
    .refine((val) => isValidIpAddress(val), {
      message: "Please enter a valid IPv4 or IPv6 address",
    }),
});

type IpFormValues = z.infer<typeof ipFormSchema>;

interface IpInputFormProps {
  onAnalyze: (ipAddress: string) => void;
  isLoading?: boolean;
}

export function IpInputForm({ onAnalyze, isLoading = false }: IpInputFormProps) {
  const [detectedVersion, setDetectedVersion] = useState<string | null>(null);

  const form = useForm<IpFormValues>({
    resolver: zodResolver(ipFormSchema),
    defaultValues: {
      ipAddress: "",
    },
  });

  const handleIpChange = (value: string) => {
    const version = getIpVersion(value);
    setDetectedVersion(version);
  };

  const onSubmit = (data: IpFormValues) => {
    onAnalyze(data.ipAddress);
  };

  const exampleIps = [
    { ip: "8.8.8.8", label: "Google DNS" },
    { ip: "1.1.1.1", label: "Cloudflare" },
    { ip: "104.16.0.1", label: "Sample" },
  ];

  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-xl font-semibold">
          <Globe className="h-5 w-5 text-primary" />
          IP Address Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="ipAddress"
              render={({ field }) => (
                <FormItem>
                  <FormControl>
                    <div className="relative">
                      <Input
                        {...field}
                        placeholder="Enter IP address (e.g., 192.168.1.1 or 2001:db8::1)"
                        className="h-14 text-lg font-mono pr-24 bg-background"
                        onChange={(e) => {
                          field.onChange(e);
                          handleIpChange(e.target.value);
                        }}
                        disabled={isLoading}
                        data-testid="input-ip-address"
                        aria-label="IP address input"
                      />
                      {detectedVersion && (
                        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-medium px-2 py-1 rounded bg-muted text-muted-foreground">
                          {detectedVersion}
                        </span>
                      )}
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button
              type="submit"
              className="w-full h-12 text-base font-medium"
              disabled={isLoading}
              data-testid="button-analyze"
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-5 w-5" />
                  Analyze IP Address
                </>
              )}
            </Button>
          </form>
        </Form>

        <div className="pt-2">
          <p className="text-xs text-muted-foreground mb-2">Try an example:</p>
          <div className="flex flex-wrap gap-2">
            {exampleIps.map(({ ip, label }) => (
              <Button
                key={ip}
                variant="outline"
                size="sm"
                onClick={() => {
                  form.setValue("ipAddress", ip);
                  handleIpChange(ip);
                }}
                disabled={isLoading}
                data-testid={`button-example-${ip.replace(/\./g, "-")}`}
                className="font-mono text-xs"
              >
                {ip}
                <span className="ml-1 text-muted-foreground">({label})</span>
              </Button>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
