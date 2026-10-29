PikaBoo - Secure Connection Through Privacy Control 

## 1. Project Overview
PikaBoo is a privacy-focused VPN gateway project designed to provide secure network connectivity through a self-hosted WireGuard VPN server. The project aims to combine a web-based dashboard, backend services, peer management, and VPN infrastructure into a unified system.

The project is currently in the development stage. Its initial implementation demonstrates VPN configuration generation, peer registration, encrypted tunnel connectivity, and internet traffic routing through a Linux-based VPN gateway. Further development is planned to improve security, reliability, usability, and deployment readiness.

## 2. Problem Statement

Internet users may connect through untrusted networks where traffic confidentiality and connection security are important concerns. Setting up and managing a personal VPN can also require technical knowledge of networking, server configuration, and key management.

PikaBoo aims to simplify interaction with VPN infrastructure through a web-based interface while exploring how a self-hosted VPN gateway can provide encrypted connections and user-controlled network routing.

## 3. Project Objectives

- Develop a web-based interface for interacting with VPN services.
- Establish encrypted network tunnels using WireGuard.
- Enable client VPN configuration generation and peer management.
- Integrate frontend, backend, database, and VPN server components.
- Configure Linux routing and network address translation for VPN traffic.
- Improve privacy, security, and usability through planned development phases.

## 4. Current Implementation

The following components have been implemented or demonstrated in the current prototype.

### 4.1 Web Dashboard

A React and TypeScript-based interface provides the initial user-facing experience. Google Sign-In is integrated into the current application flow.

### 4.2 Backend API

A Node.js API supports VPN-related operations and communication with the VPN node controller. API token authentication is used for communication with the controller.

### 4.3 VPN Configuration Generation

The application can generate and download a WireGuard client configuration. In the tested flow, client key generation occurs in the browser, and the public key is used for peer registration.

### 4.4 WireGuard VPN Server

A WireGuard server runs in a Kali Linux virtual machine. The prototype has demonstrated client peer registration, successful tunnel handshakes, and traffic transfer.

### 4.5 Network Routing

Linux IP forwarding, firewall rules, and network address translation (NAT) have been configured to allow VPN client traffic to pass through the VPN gateway and reach the internet.

### 4.6 Database Integration

PostgreSQL is included in the application architecture for application data and peer-management records.

## 5. System Architecture

The current system is composed of the following components:

User
  |
  v
React + TypeScript Dashboard
  |
  v
Backend API
  |
  v
VPN Node Controller
  |
  v
WireGuard Server (Kali Linux)
  |
  v
Linux Routing + NAT
  |
  v
Internet

PostgreSQL supports application data management. The frontend, backend, database, and VPN node form the main layers of the project.

## 6. Technologies Used


## 7. Current Testing and Results

The current prototype has been tested for the following functionality:

- Successful communication between the development environment and the VPN node controller.
- Generation and download of a client WireGuard configuration.
- Registration and verification of a client peer on the WireGuard server.
- Successful WireGuard handshake from a Windows client.
- Increasing VPN traffic counters during an active connection.
- Successful internet access while the VPN tunnel is active after network routing adjustments.

These results demonstrate that the core VPN connection workflow is functional in the tested development environment.

However, the project has not yet undergone comprehensive security auditing, large-scale testing, or production deployment validation.

## 8. Development Status

| Component | Current Status |
|---|---|
| Web dashboard | Initial implementation |
| Google authentication | Integrated and tested in the current flow |
| Backend API | Initial implementation |
| VPN configuration generation | Demonstrated |
| WireGuard peer registration | Tested |
| VPN tunnel connectivity | Tested |
| Internet routing through VPN | Demonstrated in the test environment |
| Database integration | Included in the architecture; further validation needed |
| Persistent network configuration | Requires further work |
| Production security validation | Pending |
| Production deployment | Not yet completed |

## 9. Upcoming Development Phases

PikaBoo will continue to be developed in the following phases.

### Phase 1 — Core Functionality and Stability

- Consolidate the frontend, backend, database, and VPN node integration.
- Improve error handling and validation.
- Ensure VPN routing and firewall rules persist after restarts.
- Verify peer creation, connection, disconnection, and removal workflows.

### Phase 2 — Security and Privacy Improvements

- Review authentication, API token handling, and secret management.
- Strengthen private-key handling and configuration protection.
- Investigate DNS leak prevention and IPv6 traffic handling.
- Add stricter firewall policies and test for unintended traffic leaks.
- Review logging practices to avoid exposing sensitive information.

### Phase 3 — Device and Peer Management

- Develop a more complete device-management workflow.
- Add peer revocation and configuration lifecycle management.
- Improve visibility into connection status and traffic statistics.
- Validate access control for user and device operations.

### Phase 4 — User Experience and Monitoring

- Improve dashboard usability and feedback.
- Add clearer connection status and error messages.
- Improve system health monitoring and diagnostic information.
- Test application behavior under network interruptions and server restarts.
### Phase 5 — Deployment and Validation
- Develop repeatable deployment and configuration procedures.
- Perform functional, integration, and security testing.
- Test recovery from failures and unexpected disconnections.
- Document operational requirements and limitations.
- Evaluate readiness for a controlled deployment.
*These phases represent planned work and are not yet completed.*

## 10. Current Limitations
PikaBoo remains a development prototype rather than a production-ready VPN service.
- The current test environment depends on the configured Linux virtual machine and its network connection.
- Network addresses, firewall rules, and routing behavior require reliable persistent configuration.
- DNS leak prevention and IPv6 handling require further verification.
- Comprehensive security auditing and performance testing have not been completed.
- Routing traffic through the VPN does not automatically guarantee anonymity or change the public IP address when the VPN server exits through the same internet connection as the client.

## 11. Project Goals
The long-term goal is to evolve PikaBoo into a more reliable and user-friendly VPN management system that combines encrypted connectivity, controlled peer management, and improved privacy safeguards.

Future progress will focus on validating the existing functionality, strengthening security, improving operational reliability, and preparing the system for a carefully controlled deployment.

## 12. Conclusion
PikaBoo is an ongoing project exploring the development of a self-hosted VPN gateway with a web-based management interface. Its current prototype demonstrates the integration of a frontend, backend API, WireGuard server, and Linux network routing.

The next stages will focus on persistent configuration, security improvements, device management, monitoring, and comprehensive testing. The project is being developed incrementally, with the goal of building a more secure, reliable, and practical VPN management solution.

---

**PikaBoo — Secure Connection Through Privacy Control.**
