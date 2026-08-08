#!/usr/bin/env python3
"""
Smart Crop — crop images by description using computer vision.
Usage: python3 smart_crop.py <input_image> <output_image> "<description>"

Supports:
- Card/document detection (rectangular objects with edges)
- Face detection (crop to face/person)
- Center subject detection (largest object)
- Custom region descriptions
"""

import sys
import cv2
import numpy as np
from PIL import Image

def detect_card(img):
    """Detect rectangular card-like objects using contour detection."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edged = cv2.Canny(blurred, 30, 150)
    
    # Dilate to close gaps
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
    edged = cv2.dilate(edged, kernel, iterations=2)
    
    contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    candidates = []
    img_area = img.shape[0] * img.shape[1]
    
    for c in contours:
        area = cv2.contourArea(c)
        if area < img_area * 0.05:  # Skip small contours
            continue
        
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.02 * peri, True)
        
        # Look for 4-corner shapes (rectangular like cards)
        if len(approx) >= 4 and len(approx) <= 8:
            x, y, w, h = cv2.boundingRect(approx)
            aspect = float(w) / h if h > 0 else 0
            
            # Card aspect ratios: trading cards ~0.7, playing cards ~0.69, ID cards ~1.58
            # Accept a wide range
            if 0.4 < aspect < 3.0:
                # Score by area and rectangularity
                rect_area = w * h
                fill_ratio = area / rect_area if rect_area > 0 else 0
                score = area * fill_ratio
                candidates.append((score, x, y, w, h))
    
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1:]  # Return (x, y, w, h) of best match
    
    # Fallback: find largest contour
    if contours:
        c = max(contours, key=cv2.contourArea)
        if cv2.contourArea(c) > img_area * 0.1:
            return cv2.boundingRect(c)
    
    return None

def detect_face(img):
    """Detect faces using Haar cascade."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(gray, 1.1, 5, minSize=(30, 30))
    
    if len(faces) > 0:
        # Return largest face
        areas = [w * h for (x, y, w, h) in faces]
        idx = np.argmax(areas)
        x, y, w, h = faces[idx]
        # Expand a bit around the face
        pad_x = int(w * 0.3)
        pad_y = int(h * 0.5)
        x = max(0, x - pad_x)
        y = max(0, y - pad_y)
        w = min(img.shape[1] - x, w + 2 * pad_x)
        h = min(img.shape[0] - y, h + 2 * pad_y)
        return (x, y, w, h)
    
    # Fallback: try upper body
    upper_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_upperbody.xml')
    bodies = upper_cascade.detectMultiScale(gray, 1.1, 3, minSize=(50, 50))
    if len(bodies) > 0:
        areas = [w * h for (x, y, w, h) in bodies]
        idx = np.argmax(areas)
        return tuple(bodies[idx])
    
    return None

def detect_center_subject(img):
    """Detect the main subject using GrabCut or edge-based segmentation."""
    h, w = img.shape[:2]
    
    # Use Canny edges to find the main object
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edged = cv2.Canny(blurred, 30, 100)
    
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (7, 7))
    edged = cv2.dilate(edged, kernel, iterations=3)
    edged = cv2.morphologyEx(edged, cv2.MORPH_CLOSE, kernel)
    
    contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if contours:
        # Get the largest few contours and combine
        contours = sorted(contours, key=cv2.contourArea, reverse=True)[:5]
        valid = [c for c in contours if cv2.contourArea(c) > (w * h * 0.05)]
        if valid:
            # Merge bounding boxes
            all_points = np.vstack(valid)
            x, y, cw, ch = cv2.boundingRect(all_points)
            # Add small padding
            pad = 10
            x = max(0, x - pad)
            y = max(0, y - pad)
            cw = min(w - x, cw + 2 * pad)
            ch = min(h - y, ch + 2 * pad)
            return (x, y, cw, ch)
    
    return None

def detect_text_region(img):
    """Detect regions with text (for cropping documents)."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Use MSER for text detection
    mser = cv2.MSER_create()
    mser.setMinArea(100)
    mser.setMaxArea(50000)
    
    regions, _ = mser.detectRegions(gray)
    
    if len(regions) > 0:
        # Get bounding box of all text regions
        hulls = [cv2.convexHull(p.reshape(-1, 1, 2)) for p in regions]
        all_points = np.vstack(hulls)
        x, y, w, h = cv2.boundingRect(all_points)
        return (x, y, w, h)
    
    return None

def auto_crop(img, description=""):
    """Auto-crop based on description keywords."""
    desc = description.lower().strip()
    h, w = img.shape[:2]
    
    result = None
    method = ""
    
    # Match description to detection method
    if any(kw in desc for kw in ['card', 'trading card', 'pokemon', 'tcg', 'playing card', 'id card', 'license', 'document', 'passport', 'ticket']):
        result = detect_card(img)
        method = "card/document detection"
    elif any(kw in desc for kw in ['face', 'head', 'person', 'selfie', 'portrait', 'headshot', 'me', 'someone']):
        result = detect_face(img)
        method = "face/person detection"
    elif any(kw in desc for kw in ['text', 'document', 'letter', 'page', 'screen', 'sign', 'writing']):
        result = detect_text_region(img)
        method = "text region detection"
    elif any(kw in desc for kw in ['subject', 'object', 'center', 'main', 'thing', 'item', 'product']):
        result = detect_center_subject(img)
        method = "center subject detection"
    else:
        # Try all methods, pick the best result
        for detector, name in [(detect_card, "card"), (detect_face, "face"), (detect_center_subject, "subject")]:
            r = detector(img)
            if r:
                result = r
                method = name
                break
    
    if result:
        x, y, cw, ch = result
        # Ensure minimum size
        if cw < 50 or ch < 50:
            result = None
    
    if not result:
        # Fallback: trim whitespace/borders
        gray = cv2.cvtColor(img, cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.shape[2] == 3 else img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 10, 255, cv2.THRESH_BINARY)
        coords = cv2.findNonZero(thresh)
        if coords is not None:
            x, y, w, h = cv2.boundingRect(coords)
            result = (x, y, w, h)
            method = "border trim"
        else:
            return img, "no crop applied (could not detect)"
    
    x, y, cw, ch = result
    
    # Clamp to image bounds
    x = max(0, x)
    y = max(0, y)
    cw = min(w - x, cw)
    ch = min(h - y, ch)
    
    cropped = img[y:y+ch, x:x+cw]
    
    return cropped, f"cropped via {method}: {cw}x{ch}px from ({x},{y})"

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 smart_crop.py <input> <output> <description>")
        print("Examples:")
        print("  python3 smart_crop.py input.jpg output.jpg 'crop to only leave the card'")
        print("  python3 smart_crop.py input.jpg output.jpg 'crop to face'")
        print("  python3 smart_crop.py input.jpg output.jpg 'crop to center subject'")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    description = sys.argv[3]
    
    img = cv2.imread(input_path)
    if img is None:
        print(f"Error: Could not load {input_path}")
        sys.exit(1)
    
    print(f"Loaded: {img.shape[1]}x{img.shape[0]}px")
    print(f"Description: {description}")
    
    cropped, info = auto_crop(img, description)
    print(f"Result: {info}")
    print(f"Output: {cropped.shape[1]}x{cropped.shape[0]}px")
    
    cv2.imwrite(output_path, cropped)
    print(f"Saved to: {output_path}")

if __name__ == "__main__":
    main()
