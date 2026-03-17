package com.phishwarden.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "honey_files")
public class HoneyFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String filename;

    @Enumerated(EnumType.STRING)
    private FileType fileType;

    @Column(unique = true)
    private String canaryToken;

    private int downloadCount = 0;

    private LocalDateTime createdAt = LocalDateTime.now();

    public enum FileType { INVOICE, PAYROLL, CONTRACT, CREDENTIALS }

    public HoneyFile() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public FileType getFileType() { return fileType; }
    public void setFileType(FileType fileType) { this.fileType = fileType; }

    public String getCanaryToken() { return canaryToken; }
    public void setCanaryToken(String canaryToken) { this.canaryToken = canaryToken; }

    public int getDownloadCount() { return downloadCount; }
    public void setDownloadCount(int downloadCount) { this.downloadCount = downloadCount; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}