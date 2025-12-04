from ransomware_defender import RansomwareDefender

def test_malware_detection():
    """Test if our antivirus can detect the malware"""
    defender = RansomwareDefender()
    
    # Test with the actual malware code
    test_result, patterns = defender.detect_malware_code('malware.py')
    
    print("🧪 MALWARE DETECTION TEST")
    print("=" * 50)
    
    if test_result:
        print("✅ SUCCESS: Malware detected!")
        print("📋 Detected patterns:")
        for pattern in patterns:
            print(f"   - {pattern}")
    else:
        print("❌ FAILED: Malware not detected")
    
    print("=" * 50)

if __name__ == "__main__":
    test_malware_detection()