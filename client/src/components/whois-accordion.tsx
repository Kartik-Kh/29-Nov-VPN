import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type WhoisRecord } from "@shared/schema";
import { FileText, Network, User, Server } from "lucide-react";

interface WhoisAccordionProps {
  whois: WhoisRecord | null;
}

interface WhoisFieldProps {
  label: string;
  value: string | null | undefined;
}

function WhoisField({ label, value }: WhoisFieldProps) {
  // Don't render empty fields or "Unknown" values
  if (!value || value === "Unknown") return null;
  
  return (
    <div className="space-y-1">
      <dt className="text-xs text-muted-foreground font-medium uppercase tracking-wide">
        {label}
      </dt>
      <dd
        className="text-sm font-medium break-all"
        data-testid={`text-whois-${label.toLowerCase().replace(/\s/g, "-")}`}
      >
        {value}
      </dd>
    </div>
  );
}

export function WhoisAccordion({ whois }: WhoisAccordionProps) {
  if (!whois) {
    return (
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2 text-xl font-semibold">
            <FileText className="h-5 w-5 text-primary" />
            WHOIS Records
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            <div className="text-center">
              <FileText className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">WHOIS data not available</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Count available fields in each section
  const registrationFields = [whois.registrar, whois.registrantName, whois.registrantOrg, whois.registrantCountry, whois.createdDate, whois.updatedDate, whois.expiresDate, whois.domain].filter(Boolean).length;
  const networkFields = [whois.netRange, whois.netName, whois.netHandle, whois.originAs].filter(Boolean).length;
  const hasNameServers = whois.nameServers && whois.nameServers.length > 0;
  const contactFields = [whois.abuseContact, whois.techContact].filter(Boolean).length;

  const defaultValue = [];
  if (registrationFields > 0) defaultValue.push("registration");
  if (networkFields > 0 || hasNameServers) defaultValue.push("network");
  if (contactFields > 0) defaultValue.push("contact");

  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-xl font-semibold">
          <FileText className="h-5 w-5 text-primary" />
          WHOIS Records
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Accordion type="multiple" defaultValue={defaultValue} className="space-y-2">
          {registrationFields > 0 && (
            <AccordionItem value="registration" className="border rounded-md px-4">
              <AccordionTrigger className="hover:no-underline py-3">
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">Registration Information</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="pb-4">
                <dl className="grid grid-cols-2 gap-4">
                  <WhoisField label="Registrar" value={whois.registrar} />
                  <WhoisField label="Registrant Name" value={whois.registrantName} />
                  <WhoisField label="Organization" value={whois.registrantOrg} />
                  <WhoisField label="Country" value={whois.registrantCountry} />
                  <WhoisField label="Created Date" value={whois.createdDate} />
                  <WhoisField label="Updated Date" value={whois.updatedDate} />
                  <WhoisField label="Expires Date" value={whois.expiresDate} />
                  <WhoisField label="Domain" value={whois.domain} />
                </dl>
              </AccordionContent>
            </AccordionItem>
          )}

          {(networkFields > 0 || hasNameServers) && (
            <AccordionItem value="network" className="border rounded-md px-4">
              <AccordionTrigger className="hover:no-underline py-3">
                <div className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">Network Information</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="pb-4">
                <dl className="grid grid-cols-2 gap-4">
                  <WhoisField label="Net Range" value={whois.netRange} />
                  <WhoisField label="Net Name" value={whois.netName} />
                  <WhoisField label="Net Handle" value={whois.netHandle} />
                  <WhoisField label="Origin AS" value={whois.originAs} />
                  {hasNameServers && (
                    <div className="col-span-2 space-y-1">
                      <dt className="text-xs text-muted-foreground font-medium uppercase tracking-wide">
                        Name Servers
                      </dt>
                      <dd className="text-sm font-medium">
                        <div className="flex flex-wrap gap-2">
                          {whois.nameServers.map((ns, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-muted rounded text-xs font-mono"
                            >
                              {ns}
                            </span>
                          ))}
                        </div>
                      </dd>
                    </div>
                  )}
                </dl>
              </AccordionContent>
            </AccordionItem>
          )}

          {contactFields > 0 && (
            <AccordionItem value="contact" className="border rounded-md px-4">
              <AccordionTrigger className="hover:no-underline py-3">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">Contact Information</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="pb-4">
                <dl className="grid grid-cols-2 gap-4">
                  <WhoisField label="Abuse Contact" value={whois.abuseContact} />
                  <WhoisField label="Tech Contact" value={whois.techContact} />
                </dl>
              </AccordionContent>
            </AccordionItem>
          )}
        </Accordion>
      </CardContent>
    </Card>
  );
}
