import asyncio
from cybersecurity_system import CybersecuritySystem
import platform
import os

async def main():
    # Create the cybersecurity system
    system = CybersecuritySystem()
    
    # Get system information
    os_name = platform.system()
    os_version = platform.version()
    kernel_version = platform.release()
    
    # Get installed packages (this is a simplified example)
    installed_packages = ["python3", "pip"]  # You can expand this list
    
    # Get network services (this is a simplified example)
    network_services = ["http", "https"]  # You can expand this list
    
    # Create system info dictionary
    system_info = {
        "os_name": os_name,
        "os_version": os_version,
        "kernel_version": kernel_version,
        "installed_packages": installed_packages,
        "network_services": network_services
    }
    
    try:
        # Run the analysis
        print("Starting system analysis...")
        results = await system.analyze_system(system_info)
        
        # Print the formatted report
        print("\nAnalysis Results:")
        print(results["formatted_report"])
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")

if __name__ == "__main__":
    # Make sure we have the OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable not set.")
        print("Please set your OpenAI API key in the .env file or environment variables.")
        exit(1)
    
    # Run the analysis
    asyncio.run(main()) 