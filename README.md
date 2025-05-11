# Erebrus Astro Node

The Erebrus Astro Node is a high-performance node designed for AI workloads, application orchestration, and decentralized VPN. Unlike the Beacon Node, which primarily functions as a VPN relay, Astro Nodes provide AI Agent hosting, firewall deployment, and global DNS assignment for applications deployed by users.

## Overview

Running a Astro Node allows you to earn rewards for sharing compute and storage resources, supporting decentralized AI coordination and censorship-resistant applications. Operators must have a static IP and a wildcard domain to enable seamless deployment and connectivity. While a home lab setup is possible, cloud deployment is recommended for performance and reliability.

By hosting a Astro Node, you help build a resilient AI coordination layer, enabling users to deploy AI agents, self-hosted apps like Nextcloud, and privacy-enhancing tools.

## Prerequisites

### Hardware Requirements

- Operating System: `Linux`
- Minimum Hardware Requirements:
  - `8GB RAM` (Recommended: `16GB+`)
  - `4 vCPUs` (Recommended: `8 vCPUs`)
  - `200GB+` SSD storage (Recommended: `500GB+` for AI Agents hosting)
  - Static IP required
  - Domain and Wildcard domain (for App Orchestration & DDNS Assignment)

### Network Requirements

- Incoming traffic allowed on ports:
  - `51820` (WireGuard VPN)
  - `9002` (LibP2P peer discovery)
  - `443 & 80` (Web applications & API access)
- A stable, high-bandwidth internet connection (preferably wired)
- Basic familiarity with command-line interface (CLI)
- Node Wallet (valid mnemonic on the supported chain) for on-chain registration and checkpoint

## Deployment Options

### Cloud Deployment (Recommended)

Astro Nodes require higher computing power, making cloud deployment preferable. Here's an estimated monthly cost based on recommended specifications:

| Cloud Provider | Instance Type | CPU | RAM | Storage | Static IP | Estimated Cost |
|----------------|---------------|-----|-----|---------|-----------|----------------|
| Hetzner | AX41 | 8 vCPUs | 16GB | 512GB SSD | ✅ Included | ~$50/month |
| AWS EC2 | t3.xlarge | 4 vCPUs | 16GB | 500GB SSD | ✅ $5 extra | ~$90/month |
| DigitalOcean | General Droplet | 8 vCPUs | 16GB | 500GB SSD | ✅ $5 extra | ~$80/month |
| Vultr | High-Performance | 8 vCPUs | 16GB | 500GB SSD | ✅ Included | ~$60/month |

## Requirements

- **License Fee:** A Node License NFT is required to run a Astro Node
- **Staking Requirement:** Currently $0 USD (subject to change based on demand & supply)
- **Revenue Model:** Earn rewards for both:
  - Enabling encrypted, censorship-resistant VPN
  - Hosting AI Agents & decentralized apps

## Installation

1. **Install Node Software**
    ```bash
   # If running as regular user:
   sudo bash <(curl -s https://raw.githubusercontent.com/NetSepio/astro/main/install.sh)
   
   # If running as root:
   bash <(curl -s https://raw.githubusercontent.com/NetSepio/astro/main/install.sh)
   ```

2. **Configure Node Parameters**
   - Set up public IP and wildcard domain
   - Choose resource allocation for AI compute & app hosting
   - Configure firewall settings for security

3. **Verification Process**
   - Ensure all necessary ports are open
   - Test AI workload execution & VPN reachability

## Maintenance & Monitoring

- Update your node software regularly for performance & security patches
- Monitor system usage (CPU, RAM, storage) to ensure smooth operation
- Use logging tools to track AI task execution & app deployments

## Security Considerations

- Protect your Node Operator account mnemonic
- Keep SSH secure
- Regularly update node software and dependencies
- Monitor system resources and logs

## Additional Resources

- [Erebrus Documentation](https://docs.netsepio.com/latest/erebrus/nodes/astro-node)
- [Support Discord](https://discord.gg/netsepio)


## License

This project requires a Node License NFT to operate.
