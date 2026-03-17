package com.phishwarden.controller;

import com.phishwarden.model.HoneyFile;
import com.phishwarden.service.HoneyFileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
@CrossOrigin(origins = {"http://localhost:5500", "http://127.0.0.1:5500"})
public class FileController {

    @Autowired
    private HoneyFileService honeyFileService;

    @GetMapping
    public ResponseEntity<List<HoneyFile>> listFiles() {
        return ResponseEntity.ok(honeyFileService.getAllHoneyFiles());
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> download(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean honey) throws Exception {

        byte[] data = honeyFileService.serveFile(id, honey);
        String filename = honey
                ? "document_" + id + ".xlsx"
                : "real_document_" + id + ".xlsx";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(data);
    }

    @PostMapping("/create")
    public ResponseEntity<HoneyFile> createFile(@RequestBody Map<String, String> body) {
        HoneyFile hf = honeyFileService.createHoneyFile(
                body.get("filename"),
                HoneyFile.FileType.valueOf(body.get("fileType"))
        );
        return ResponseEntity.ok(hf);
    }
}
