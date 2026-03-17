-- MySQL dump 10.13  Distrib 8.0.41, for Win64 (x86_64)
--
-- Host: localhost    Database: phishwarden
-- ------------------------------------------------------
-- Server version	8.0.41

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `canary_pings`
--

DROP TABLE IF EXISTS `canary_pings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `canary_pings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `canary_token` varchar(128) NOT NULL,
  `attacker_ip` varchar(45) NOT NULL,
  `attacker_user_agent` text,
  `geo_country` varchar(100) DEFAULT NULL,
  `geo_city` varchar(100) DEFAULT NULL,
  `ping_type` enum('FILE_OPEN','FILE_ENCRYPT_ATTEMPT','EXFIL_ATTEMPT') DEFAULT 'FILE_OPEN',
  `triggered_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `canary_token` (`canary_token`),
  CONSTRAINT `canary_pings_ibfk_1` FOREIGN KEY (`canary_token`) REFERENCES `honey_files` (`canary_token`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `canary_pings`
--

LOCK TABLES `canary_pings` WRITE;
/*!40000 ALTER TABLE `canary_pings` DISABLE KEYS */;
/*!40000 ALTER TABLE `canary_pings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `honey_files`
--

DROP TABLE IF EXISTS `honey_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `honey_files` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) NOT NULL,
  `file_type` enum('INVOICE','PAYROLL','CONTRACT','CREDENTIALS') NOT NULL,
  `canary_token` varchar(128) NOT NULL,
  `download_count` int DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `canary_token` (`canary_token`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `honey_files`
--

LOCK TABLES `honey_files` WRITE;
/*!40000 ALTER TABLE `honey_files` DISABLE KEYS */;
INSERT INTO `honey_files` VALUES (1,'Payroll_Q1_2025.xlsx','PAYROLL','10fa8453-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29'),(2,'Invoice_Supplier_March.pdf','INVOICE','10fa9047-2114-11f1-8bf2-047c16aa34c1',3,'2026-03-16 08:42:29'),(3,'Employee_Credentials_2025.txt','CREDENTIALS','10fa91ee-2114-11f1-8bf2-047c16aa34c1',3,'2026-03-16 08:42:29'),(4,'Contract_NDA_Vendor.docx','CONTRACT','10fa933b-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29');
/*!40000 ALTER TABLE `honey_files` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `honeytokens`
--

DROP TABLE IF EXISTS `honeytokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `honeytokens` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `fake_email` varchar(150) NOT NULL,
  `fake_password` varchar(255) NOT NULL,
  `token_uid` varchar(64) NOT NULL,
  `is_triggered` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `fake_email` (`fake_email`),
  UNIQUE KEY `token_uid` (`token_uid`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `honeytokens`
--

LOCK TABLES `honeytokens` WRITE;
/*!40000 ALTER TABLE `honeytokens` DISABLE KEYS */;
INSERT INTO `honeytokens` VALUES (1,'admin@smallbiz.com','Admin@2024','10f92b0a-2114-11f1-8bf2-047c16aa34c1',1,'2026-03-16 08:42:29'),(2,'finance@smallbiz.com','Finance123!','10f9370e-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29'),(3,'hr@smallbiz.com','HR_Pass2024','10f939cc-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29'),(4,'ceo@smallbiz.com','Ceo$ecure1','10f93c5d-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29'),(5,'backup@smallbiz.com','Backup#Pass99','10f93eda-2114-11f1-8bf2-047c16aa34c1',0,'2026-03-16 08:42:29');
/*!40000 ALTER TABLE `honeytokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_attempts`
--

DROP TABLE IF EXISTS `login_attempts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `login_attempts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `email_used` varchar(150) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text,
  `attempt_type` enum('REAL_USER','HONEYTOKEN_HIT','BRUTE_FORCE','UNKNOWN') DEFAULT 'UNKNOWN',
  `was_successful` tinyint(1) DEFAULT '0',
  `attempted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=112 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_attempts`
--

LOCK TABLES `login_attempts` WRITE;
/*!40000 ALTER TABLE `login_attempts` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_attempts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sessions`
--

DROP TABLE IF EXISTS `sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sessions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_token` varchar(255) NOT NULL,
  `user_id` bigint DEFAULT NULL,
  `is_honey_session` tinyint(1) DEFAULT '0',
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_token` (`session_token`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sessions`
--

LOCK TABLES `sessions` WRITE;
/*!40000 ALTER TABLE `sessions` DISABLE KEYS */;
/*!40000 ALTER TABLE `sessions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `threat_events`
--

DROP TABLE IF EXISTS `threat_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `threat_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `event_type` enum('HONEYTOKEN_LOGIN','PHISHING_CRED_HARVEST','BRUTE_FORCE','CANARY_PING','PRIVILEGE_ESCALATION') DEFAULT NULL,
  `severity` enum('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT 'MEDIUM',
  `attacker_ip` varchar(45) DEFAULT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `is_resolved` tinyint(1) DEFAULT '0',
  `occurred_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=82 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `threat_events`
--

LOCK TABLES `threat_events` WRITE;
/*!40000 ALTER TABLE `threat_events` DISABLE KEYS */;
/*!40000 ALTER TABLE `threat_events` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('EMPLOYEE','ADMIN') DEFAULT 'EMPLOYEE',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `is_active` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'Alice Johnson','bhaveshpahujaonline@gmail.com','$2a$12$6qWylTr8CASR5ifSDMMO2O3e5pEa.ktf7A6Zqw7nvN3wUvyhBhj3C','EMPLOYEE','2026-03-16 08:42:29',1),(2,'Bob Singh','tanishasonionline@gmail.com','$2a$12$haibPoT8TaXiuy91t6LL7.ewVfp46uaOCHCeIbIwc1Zp2QkikpwCS','EMPLOYEE','2026-03-16 08:42:29',1),(3,'Carol Admin','harshuu2987@gmail.com','$2a$12$xwzoXnVcn1ZcC.NmAuEByutOcyZs6e.IE0pJHqrVvB8pXjwzIY1a2','ADMIN','2026-03-16 08:42:29',1);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-03-17 17:29:53
