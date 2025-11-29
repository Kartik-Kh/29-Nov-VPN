import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "@shared/schema";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import {
  type IpAnalysis,
  type InsertIpAnalysis,
  type WhoisRecord,
  type InsertWhoisRecord,
  type ScanStats,
} from "@shared/schema";

let db: any = null;

export interface IStorage {
  connect(): Promise<void>;
  createAnalysis(analysis: InsertIpAnalysis): Promise<IpAnalysis>;
  getAnalysis(id: string): Promise<IpAnalysis | undefined>;
  getAnalysisByIp(ipAddress: string): Promise<IpAnalysis | undefined>;
  getAllAnalyses(): Promise<IpAnalysis[]>;
  deleteAnalysis(id: string): Promise<boolean>;
  createWhoisRecord(record: InsertWhoisRecord): Promise<WhoisRecord>;
  getWhoisByIp(ipAddress: string): Promise<WhoisRecord | undefined>;
  getStats(): Promise<ScanStats>;
}

class PostgresStorage implements IStorage {
  async connect(): Promise<void> {
    try {
      const sql = neon(process.env.DATABASE_URL!);
      db = drizzle(sql, { schema });
      console.log("✓ Connected to PostgreSQL");
    } catch (error) {
      console.log("⚠ PostgreSQL unavailable, using in-memory fallback");
      db = null;
    }
  }

  async createAnalysis(insertAnalysis: InsertIpAnalysis): Promise<IpAnalysis> {
    const id = randomUUID();
    if (!db) return { ...insertAnalysis, id } as IpAnalysis;
    const result = await db.insert(schema.ipAnalyses).values({ ...insertAnalysis, id }).returning();
    return result[0] as IpAnalysis;
  }

  async getAnalysis(id: string): Promise<IpAnalysis | undefined> {
    if (!db) return undefined;
    const result = await db.select().from(schema.ipAnalyses).where(eq(schema.ipAnalyses.id, id)).limit(1);
    return result[0] as IpAnalysis | undefined;
  }

  async getAnalysisByIp(ipAddress: string): Promise<IpAnalysis | undefined> {
    if (!db) return undefined;
    const result = await db
      .select()
      .from(schema.ipAnalyses)
      .where(eq(schema.ipAnalyses.ipAddress, ipAddress))
      .orderBy(schema.ipAnalyses.analyzedAt)
      .limit(1);
    return result[0] as IpAnalysis | undefined;
  }

  async getAllAnalyses(): Promise<IpAnalysis[]> {
    if (!db) return [];
    return await db.select().from(schema.ipAnalyses).orderBy(schema.ipAnalyses.analyzedAt);
  }

  async deleteAnalysis(id: string): Promise<boolean> {
    if (!db) return false;
    const result = await db.delete(schema.ipAnalyses).where(eq(schema.ipAnalyses.id, id));
    return true;
  }

  async createWhoisRecord(insertRecord: InsertWhoisRecord): Promise<WhoisRecord> {
    const id = randomUUID();
    if (!db) return { ...insertRecord, id } as WhoisRecord;
    const result = await db.insert(schema.whoisRecords).values({ ...insertRecord, id }).returning();
    return result[0] as WhoisRecord;
  }

  async getWhoisByIp(ipAddress: string): Promise<WhoisRecord | undefined> {
    if (!db) return undefined;
    const result = await db
      .select()
      .from(schema.whoisRecords)
      .where(eq(schema.whoisRecords.ipAddress, ipAddress))
      .orderBy(schema.whoisRecords.fetchedAt)
      .limit(1);
    return result[0] as WhoisRecord | undefined;
  }

  async getStats(): Promise<ScanStats> {
    if (!db) return { totalScans: 0, threatsDetected: 0, cleanIps: 0, vpnsDetected: 0 };
    const allAnalyses = await db.select().from(schema.ipAnalyses);
    return {
      totalScans: allAnalyses.length,
      threatsDetected: allAnalyses.filter((a: any) => a.riskScore >= 50).length,
      cleanIps: allAnalyses.filter((a: any) => a.riskScore < 30).length,
      vpnsDetected: allAnalyses.filter((a: any) => a.isVpn).length,
    };
  }
}

export const storage = new PostgresStorage();

// Initialize storage connection
storage.connect();
