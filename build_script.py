import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_icon():
    """Create a simple icon file using PIL."""
    from PIL import Image, ImageDraw
    
    # Create a 256x256 image with a transparent background
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a shield shape
    points = [
        (size//2, 0),  # top
        (size, size//4),  # right top
        (size, size*3//4),  # right bottom
        (size//2, size),  # bottom
        (0, size*3//4),  # left bottom
        (0, size//4),  # left top
    ]
    
    # Draw the shield with a gradient
    for i in range(size//2):
        color = (0, 120 + i//2, 255 - i//2, 255)  # Blue gradient
        draw.polygon(points, fill=color)
        points = [(x-1, y) for x, y in points]
    
    # Save as ICO
    image.save('icon.ico', format='ICO')

def install_dependencies():
    """Install all required dependencies."""
    dependencies = [
        'langgraph==0.0.10',
        'langchain==0.1.0',
        'langchain-openai==0.0.2',
        'python-dotenv==1.0.0',
        'requests==2.31.0',
        'beautifulsoup4==4.12.2',
        'pydantic==2.5.2',
        'rich==13.7.0',
        'pyinstaller==6.3.0',
        'pillow==10.2.0',
        'langchain-core==0.1.27',
        'pydantic-core==2.14.5'
    ]
    
    try:
        # First, uninstall existing packages
        for dep in dependencies:
            package_name = dep.split('==')[0]
            subprocess.run([sys.executable, '-m', 'pip', 'uninstall', '-y', package_name],
                         capture_output=True, text=True)
        
        # Install dependencies with specific versions
        for dep in dependencies:
            print(f"\nInstalling {dep}...")
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', dep],
                capture_output=True,
                text=True,
                check=True
            )
            print(result.stdout)
            
        print("\nAll dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"\nError installing dependencies: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def get_pyinstaller_path():
    """Get the path to the PyInstaller executable."""
    try:
        # Get the Python installation directory
        python_dir = os.path.dirname(sys.executable)
        print(f"Python directory: {python_dir}")
        
        # Try to find PyInstaller in the Scripts directory
        scripts_dir = os.path.join(python_dir, 'Scripts')
        print(f"Looking in Scripts directory: {scripts_dir}")
        
        if os.path.exists(scripts_dir):
            pyinstaller_path = os.path.join(scripts_dir, 'pyinstaller.exe')
            if os.path.exists(pyinstaller_path):
                print(f"Found PyInstaller at: {pyinstaller_path}")
                return pyinstaller_path
        
        # If not found, try to find it in the site-packages directory
        import site
        print("Site packages directories:")
        for path in site.getsitepackages():
            print(f"Checking: {path}")
            scripts_path = os.path.join(path, 'Scripts', 'pyinstaller.exe')
            if os.path.exists(scripts_path):
                print(f"Found PyInstaller at: {scripts_path}")
                return scripts_path
        
        # If still not found, try to find it in the user's local packages
        local_packages = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Packages')
        if os.path.exists(local_packages):
            for package in os.listdir(local_packages):
                if 'PythonSoftwareFoundation.Python' in package:
                    python_path = os.path.join(local_packages, package)
                    scripts_path = os.path.join(python_path, 'LocalCache', 'local-packages', 'python313', 'Scripts', 'pyinstaller.exe')
                    if os.path.exists(scripts_path):
                        print(f"Found PyInstaller at: {scripts_path}")
                        return scripts_path
        
        print("Could not find PyInstaller in any of the expected locations")
        return None
        
    except Exception as e:
        print(f"Error finding PyInstaller: {e}")
        return None

def build_executable():
    """Build the executable using PyInstaller."""
    # Create icon if it doesn't exist
    if not os.path.exists('icon.ico'):
        create_icon()
    
    # Install dependencies
    print("\nInstalling dependencies...")
    install_dependencies()
    
    # Get PyInstaller path
    pyinstaller_path = get_pyinstaller_path()
    if not pyinstaller_path:
        print("\nCould not find PyInstaller. Please try these steps manually:")
        print("1. Open Command Prompt as Administrator")
        print("2. Run: pip uninstall pyinstaller")
        print("3. Run: pip install pyinstaller")
        print("4. Run: where pyinstaller")
        print("\nThen run this script again.")
        sys.exit(1)
    
    print(f"\nUsing PyInstaller at: {pyinstaller_path}")
    
    # Build the executable
    try:
        print("\nStarting build process...")
        result = subprocess.run([
            pyinstaller_path,
            '--clean',
            '--noconfirm',
            '--onefile',
            '--windowed',
            '--icon=icon.ico',
            '--name=CybersecuritySystem',
            '--add-data=agents;agents',
            '--add-data=.env.example;.',
            '--hidden-import=pydantic.deprecated.decorator',
            '--hidden-import=pydantic_core',
            '--hidden-import=pydantic_migration',
            '--hidden-import=pydantic_internal_validators',
            '--hidden-import=langchain_core',
            '--hidden-import=langchain_core.tools',
            '--hidden-import=langchain_core.tools.base',
            '--hidden-import=langgraph.prebuilt',
            '--hidden-import=langgraph.prebuilt.chat_agent_executor',
            '--hidden-import=langgraph.graph',
            '--hidden-import=langgraph.prebuilt.tool_executor',
            'gui.py'
        ], capture_output=True, text=True, check=True)
        
        print("\nBuild output:")
        print(result.stdout)
        
        # Create distribution directory
        dist_dir = Path('dist')
        dist_dir.mkdir(exist_ok=True)
        
        # Copy executable to distribution directory
        exe_path = Path('dist/CybersecuritySystem.exe')
        if exe_path.exists():
            shutil.copy2(str(exe_path), str(dist_dir / 'CybersecuritySystem.exe'))
            
            # Create a simple README for the distribution
            with open('dist/README.txt', 'w') as f:
                f.write("""AI-Driven Cybersecurity System

1. Double-click CybersecuritySystem.exe to run the application
2. Enter your system information in the GUI
3. Click "Analyze System" to start the analysis
4. View the results in the output window

Note: You need an OpenAI API key to use this application.
Create a .env file in the same directory with your API key:
OPENAI_API_KEY=your-api-key-here
""")
            
            print("\nBuild complete! Executable is in the 'dist' directory.")
        else:
            print("\nError: Executable was not created successfully")
            print("Check the build output above for errors.")
            
    except subprocess.CalledProcessError as e:
        print(f"\nError building executable: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build_executable() 