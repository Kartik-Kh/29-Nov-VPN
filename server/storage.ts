import mongoose from "mongoose";
import {
  type IpAnalysis,
  type InsertIpAnalysis,
  type WhoisRecord,
  type InsertWhoisRecord,
  type ScanStats,
} from "@shared/schema";
import { randomUUID } from "crypto";

const MONGODB_URL = process.env.MONGODB_URI || process.env.DATABASE_URL || "mongodb://localhost/vpn-detector";

let useDatabase = false;

// In-memory storage as fallback
const memoryAnalyses = new Map<string, IpAnalysis>();
const memoryWhois = new Map<string, WhoisRecord>();

const analysisSchema = new mongoose.Schema({
  ipAddress: String,
  ipVersion: String,
  riskScore: Number,
  isVpn: Boolean,
  isProxy: Boolean,
  isTor: Boolean,
  isDatacenter: Boolean,
  threatLevel: String,
  isp: String,
  organization: String,
  asn: String,
  country: String,
  countryCode: String,
  city: String,
  region: String,
  latitude: Number,
  longitude: Number,
  timezone: String,
  analyzedAt: Date,
}, { timestamps: true });

const whoisSchema = new mongoose.Schema({
  ipAddress: String,
  domain: String,
  registrar: String,
  registrantName: String,
  registrantOrg: String,
  registrantCountry: String,
  createdDate: String,
  updatedDate: String,
  expiresDate: String,
  nameServers: [String],
  netRange: String,
  netName: String,
  netHandle: String,
  originAs: String,
  abuseContact: String,
  techContact: String,
  fetchedAt: Date,
}, { timestamps: true });

const AnalysisModel = mongoose.model("Analysis", analysisSchema);
const WhoisModel = mongoose.model("Whois", whoisSchema);

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

class MongoStorage implements IStorage {
  async connect(): Promise<void> {
    try {
      await mongoose.connect(MONGODB_URL);
      useDatabase = true;
      console.log("✓ Connected to MongoDB");
    } catch (error) {
      console.log("⚠ MongoDB unavailable, using in-memory storage");
      useDatabase = false;
    }
  }

  async createAnalysis(insertAnalysis: InsertIpAnalysis): Promise<IpAnalysis> {
    const id = randomUUID();
    const analysis: IpAnalysis = {
      ...insertAnalysis,
      id,
      isp: insertAnalysis.isp ?? null,
      organization: insertAnalysis.organization ?? null,
      timezone: insertAnalysis.timezone ?? null,
    } as IpAnalysis;
    
    memoryAnalyses.set(id, analysis);
    
    if (!useDatabase) return analysis;
    
    try {
      const doc = await AnalysisModel.create(insertAnalysis);
      return { ...doc.toObject(), id: doc._id.toString() } as IpAnalysis;
    } catch (error) {
      return analysis;
    }
  }

  async getAnalysis(id: string): Promise<IpAnalysis | undefined> {
    if (!useDatabase) return undefined;
    const doc = await AnalysisModel.findById(id);
    return doc ? ({ ...doc.toObject(), id: doc._id.toString() } as IpAnalysis) : undefined;
  }

  async getAnalysisByIp(ipAddress: string): Promise<IpAnalysis | undefined> {
    if (!useDatabase) return undefined;
    const doc = await AnalysisModel.findOne({ ipAddress }).sort({ analyzedAt: -1 });
    return doc ? ({ ...doc.toObject(), id: doc._id.toString() } as IpAnalysis) : undefined;
  }

  async getAllAnalyses(): Promise<IpAnalysis[]> {
    if (useDatabase) {
      try {
        const docs = await AnalysisModel.find().sort({ analyzedAt: -1 });
        return docs.map((doc) => ({ ...doc.toObject(), id: doc._id.toString() } as IpAnalysis));
      } catch {
        return Array.from(memoryAnalyses.values()).sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime());
      }
    }
    return Array.from(memoryAnalyses.values()).sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime());
  }

  async deleteAnalysis(id: string): Promise<boolean> {
    if (!useDatabase) return false;
    const result = await AnalysisModel.deleteOne({ _id: id });
    return result.deletedCount > 0;
  }

  async createWhoisRecord(insertRecord: InsertWhoisRecord): Promise<WhoisRecord> {
    const id = randomUUID();
    const whois: WhoisRecord = {
      ...insertRecord,
      id,
      domain: insertRecord.domain ?? null,
      registrar: insertRecord.registrar ?? null,
      registrantName: insertRecord.registrantName ?? null,
      registrantOrg: insertRecord.registrantOrg ?? null,
      registrantCountry: insertRecord.registrantCountry ?? null,
      createdDate: insertRecord.createdDate ?? null,
      updatedDate: insertRecord.updatedDate ?? null,
      expiresDate: insertRecord.expiresDate ?? null,
      nameServers: insertRecord.nameServers ?? null,
      netRange: insertRecord.netRange ?? null,
      netName: insertRecord.netName ?? null,
      netHandle: insertRecord.netHandle ?? null,
      originAs: insertRecord.originAs ?? null,
      abuseContact: insertRecord.abuseContact ?? null,
      techContact: insertRecord.techContact ?? null,
    } as WhoisRecord;
    
    memoryWhois.set(insertRecord.ipAddress, whois);
    
    if (!useDatabase) return whois;
    
    try {
      const doc = await WhoisModel.create(insertRecord);
      return { ...doc.toObject(), id: doc._id.toString() } as WhoisRecord;
    } catch (error) {
      return whois;
    }
  }

  async getWhoisByIp(ipAddress: string): Promise<WhoisRecord | undefined> {
    if (!useDatabase) return undefined;
    const doc = await WhoisModel.findOne({ ipAddress }).sort({ fetchedAt: -1 });
    return doc ? ({ ...doc.toObject(), id: doc._id.toString() } as WhoisRecord) : undefined;
  }

  async getStats(): Promise<ScanStats> {
    let allAnalyses: any[] = [];
    
    if (useDatabase) {
      try {
        allAnalyses = await AnalysisModel.find();
      } catch {
        allAnalyses = Array.from(memoryAnalyses.values());
      }
    } else {
      allAnalyses = Array.from(memoryAnalyses.values());
    }
    
    return {
      totalScans: allAnalyses.length,
      threatsDetected: allAnalyses.filter((a) => (a.riskScore ?? 0) >= 50).length,
      cleanIps: allAnalyses.filter((a) => (a.riskScore ?? 0) < 30).length,
      vpnsDetected: allAnalyses.filter((a) => a.isVpn).length,
    };
  }
}

export const storage = new MongoStorage();

// Initialize storage connection
storage.connect();
