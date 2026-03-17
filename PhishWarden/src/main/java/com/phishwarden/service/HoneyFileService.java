package com.phishwarden.service;

import com.phishwarden.model.HoneyFile;
import com.phishwarden.repository.HoneyFileRepository;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * HoneyFileService
 *
 * Generates convincing fake documents that:
 *   1. Look exactly like real company files (invoices, payroll, credentials)
 *   2. Contain an invisible canary token URL embedded as a hidden cell / comment
 *   3. When an attacker opens the file OR tries to "encrypt" it, they may
 *      trigger a DNS/HTTP callback to our canary endpoint — revealing their IP
 *
 * For the hackathon demo: we simulate the canary via a hidden Excel cell
 * containing a formula that would ping our endpoint if Excel auto-resolves URLs.
 */
@Service
public class HoneyFileService {

    @Autowired private HoneyFileRepository honeyFileRepo;

    @Value("${phishwarden.canary.callback-base-url}")
    private String canaryBaseUrl;

    // ── Serve file to a session ────────────────────────────────────
    // isHoney = true  → return honey file (attacker sees convincing fake)
    // isHoney = false → return real file (employee gets real data)
    public byte[] serveFile(Long fileId, boolean isHoney) throws Exception {
        Optional<HoneyFile> hfOpt = honeyFileRepo.findById(fileId);
        if (hfOpt.isEmpty()) throw new RuntimeException("File not found");

        HoneyFile hf = hfOpt.get();

        if (!isHoney) {
            // Real employees get placeholder — in prod, serve from secure storage
            return ("REAL_FILE_CONTENT_" + hf.getFilename()).getBytes();
        }

        // Increment download counter (attacker is downloading)
        hf.setDownloadCount(hf.getDownloadCount() + 1);
        honeyFileRepo.save(hf);

        // Generate the appropriate honey file type
        return switch (hf.getFileType()) {
            case PAYROLL     -> generateHoneyPayroll(hf);
            case INVOICE     -> generateHoneyInvoice(hf);
            case CREDENTIALS -> generateHoneyCredentials(hf);
            case CONTRACT    -> generateHoneyContract(hf);
        };
    }

    // ── Honey Payroll XLSX ─────────────────────────────────────────
    private byte[] generateHoneyPayroll(HoneyFile hf) throws Exception {
        try (XSSFWorkbook wb = new XSSFWorkbook()) {
            Sheet sheet = wb.createSheet("Payroll Q1 2025");

            // Canary URL embedded in a hidden row (row 1000)
            // If Excel resolves external links, it pings our server
            String canaryUrl = canaryBaseUrl + "/api/canary/ping?token=" + hf.getCanaryToken() + "&t=open";
            Row hiddenRow = sheet.createRow(1000);
            hiddenRow.setZeroHeight(true); // hidden
            hiddenRow.createCell(0).setCellValue(canaryUrl);

            // Convincing payroll header
            CellStyle headerStyle = wb.createCellStyle();
            Font headerFont = wb.createFont();
            headerFont.setBold(true);
            headerStyle.setFont(headerFont);

            Row header = sheet.createRow(0);
            String[] cols = {"Employee ID","Name","Department","Base Salary","Bonus","Net Pay","Bank Account"};
            for (int i = 0; i < cols.length; i++) {
                Cell c = header.createCell(i);
                c.setCellValue(cols[i]);
                c.setCellStyle(headerStyle);
            }

            // Fake but convincing payroll data
            Object[][] data = {
                {"EMP001","Alice Johnson","Engineering",   85000, 5000, 78450, "****4521"},
                {"EMP002","Bob Singh",    "Sales",         72000, 8500, 70200, "****7834"},
                {"EMP003","Carol Admin",  "Management",   120000,15000,112500, "****2290"},
                {"EMP004","David Patel",  "Marketing",     65000, 3500, 61800, "****9012"},
                {"EMP005","Emma Torres",  "HR",            68000, 2000, 63100, "****3345"},
            };
            for (int r = 0; r < data.length; r++) {
                Row row = sheet.createRow(r + 1);
                for (int c = 0; c < data[r].length; c++) {
                    Cell cell = row.createCell(c);
                    if (data[r][c] instanceof Integer) cell.setCellValue((Integer) data[r][c]);
                    else cell.setCellValue(data[r][c].toString());
                }
            }

            // Auto-size columns
            for (int i = 0; i < cols.length; i++) sheet.autoSizeColumn(i);

            // Embed canary in document properties (additional tracking vector)
            wb.getProperties().getCoreProperties().setDescription(
                "Document ID: " + hf.getCanaryToken()
            );

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            wb.write(out);
            return out.toByteArray();
        }
    }

    // ── Honey Invoice XLSX ─────────────────────────────────────────
    private byte[] generateHoneyInvoice(HoneyFile hf) throws Exception {
        try (XSSFWorkbook wb = new XSSFWorkbook()) {
            Sheet sheet = wb.createSheet("Invoice");

            // Canary comment on cell A1 - looks like a doc ID
            Row r0 = sheet.createRow(0);
            r0.createCell(0).setCellValue("INVOICE #INV-2025-0847");
            r0.createCell(1).setCellValue("SmallBiz Corp.");

            sheet.createRow(2).createCell(0).setCellValue("Bill To: Vendor ABC Ltd");
            sheet.createRow(3).createCell(0).setCellValue("Date: March 2025");
            sheet.createRow(4).createCell(0).setCellValue("Due: April 2025");

            Row itemHeader = sheet.createRow(6);
            itemHeader.createCell(0).setCellValue("Description");
            itemHeader.createCell(1).setCellValue("Qty");
            itemHeader.createCell(2).setCellValue("Unit Price");
            itemHeader.createCell(3).setCellValue("Total");

            Object[][] items = {
                {"Software License Q1", 5, 1200.00, 6000.00},
                {"Support & Maintenance", 1, 2500.00, 2500.00},
                {"Cloud Hosting (Annual)", 1, 4800.00, 4800.00},
            };
            for (int i = 0; i < items.length; i++) {
                Row row = sheet.createRow(7 + i);
                row.createCell(0).setCellValue(items[i][0].toString());
                row.createCell(1).setCellValue((Integer) items[i][1]);
                row.createCell(2).setCellValue((Double) items[i][2]);
                row.createCell(3).setCellValue((Double) items[i][3]);
            }

            // Hidden canary row
            Row canaryRow = sheet.createRow(999);
            canaryRow.setZeroHeight(true);
            canaryRow.createCell(0).setCellValue(
                canaryBaseUrl + "/api/canary/ping?token=" + hf.getCanaryToken() + "&t=open"
            );

            wb.getProperties().getCoreProperties().setDescription("RefID: " + hf.getCanaryToken());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            wb.write(out);
            return out.toByteArray();
        }
    }

    // ── Honey Credentials TXT ──────────────────────────────────────
    private byte[] generateHoneyCredentials(HoneyFile hf) {
        // A plain text file attackers love to find — but every "credential"
        // is a honeytoken that will alert us when used
        String content = """
            # SmallBiz Internal Credentials - CONFIDENTIAL
            # Last updated: March 2025
            # Document ID: %s
            
            == Email System ==
            mail-admin@smallbiz.com / MailAdmin2025!
            
            == Cloud Storage ==
            backup-service@smallbiz.com / BackupS3cur3#99
            
            == Database ==
            db-readonly@smallbiz.com / DBRead0nly$2025
            
            == VPN ==
            vpn-gateway: 192.168.1.1
            vpn-user: vpnuser@smallbiz.com
            vpn-pass: VPN@SecureKey2025
            
            # Canary: %s
            """.formatted(hf.getCanaryToken(), canaryBaseUrl + "/api/canary/ping?token=" + hf.getCanaryToken());

        // All passwords above are honeytokens seeded in the honeytokens table
        return content.getBytes();
    }

    // ── Honey Contract (plain text for simplicity) ─────────────────
    private byte[] generateHoneyContract(HoneyFile hf) {
        String content = """
            NON-DISCLOSURE AGREEMENT
            Document Reference: %s
            
            This agreement is entered into between SmallBiz Corp ("Company")
            and [Vendor Name] ("Recipient") effective March 2025.
            
            1. CONFIDENTIAL INFORMATION
            Recipient agrees to hold in strict confidence all proprietary
            information including but not limited to: financial data,
            employee records, customer lists, and technical specifications.
            
            2. OBLIGATIONS
            ...
            
            [This document contains a tracking identifier. Any unauthorized
            access will be logged and reported to law enforcement.]
            """.formatted(hf.getCanaryToken());
        return content.getBytes();
    }

    // ── List all honey files (for SOC dashboard) ──────────────────
    public List<HoneyFile> getAllHoneyFiles() {
        return honeyFileRepo.findAllByOrderByCreatedAtDesc();
    }

    // ── Generate a fresh honey file and save to DB ─────────────────
    public HoneyFile createHoneyFile(String filename, HoneyFile.FileType type) {
        HoneyFile hf = new HoneyFile();
        hf.setFilename(filename);
        hf.setFileType(type);
        hf.setCanaryToken(UUID.randomUUID().toString().replace("-", ""));
        return honeyFileRepo.save(hf);
    }
}
