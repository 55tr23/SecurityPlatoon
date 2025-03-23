# AI-Driven Cybersecurity System

An intelligent cybersecurity system that uses multiple specialized AI agents to analyze, test, and secure operating systems. The system leverages LangGraph to coordinate multiple agents that work together to identify vulnerabilities, simulate attacks, develop patches, and generate comprehensive reports.

## Features

- **Threat Analysis Agent**: Scans multiple cybersecurity databases (CVE, NVD, CISA) to identify known vulnerabilities
- **Penetration Agent**: Simulates attacks on identified vulnerabilities to assess system weaknesses
- **Patching Agent**: Develops and applies patches to mitigate vulnerabilities
- **Reporting Agent**: Generates comprehensive, human-readable reports with findings and recommendations

## Prerequisites

- Python 3.8+
- OpenAI API key
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your OpenAI API key
```

## Usage

1. Basic usage:
```python
from cybersecurity_system import CybersecuritySystem
import asyncio

async def main():
    system = CybersecuritySystem()
    
    system_info = {
        "os_name": "Ubuntu",
        "os_version": "22.04 LTS",
        "kernel_version": "5.15.0-91-generic",
        "installed_packages": ["nginx", "postgresql", "python3", "docker"],
        "network_services": ["ssh", "http", "https", "postgresql"]
    }
    
    results = await system.analyze_system(system_info)
    print(results["formatted_report"])

if __name__ == "__main__":
    asyncio.run(main())
```

2. Run the example script:
```bash
python cybersecurity_system.py
```

## System Architecture

The system uses LangGraph to coordinate four specialized agents:

1. **Threat Analysis Agent**
   - Scans multiple cybersecurity databases
   - Classifies vulnerabilities by severity
   - Identifies potential attack vectors

2. **Penetration Agent**
   - Simulates attacks on identified vulnerabilities
   - Assesses exploitability
   - Documents attack methodologies

3. **Patching Agent**
   - Develops patches for vulnerabilities
   - Provides implementation steps
   - Includes rollback procedures

4. **Reporting Agent**
   - Generates comprehensive reports
   - Provides executive summaries
   - Lists technical details and recommendations

## Output

The system generates a rich-formatted report containing:
- Executive summary
- Technical details
- Vulnerability table
- Recommendations
- Implementation steps
- Risk assessments

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This system is for educational and research purposes only. Always obtain proper authorization before performing security testing on any system. 