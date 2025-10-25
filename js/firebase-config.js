// Firebase Configuration - No Authentication Required
class FirebaseManager {
    constructor() {
        this.isConnected = false;
        this.db = null;
        this.userId = this.generateUserId(); // Generate unique user ID for local storage
        
        this.initFirebase();
    }

    initFirebase() {
        try {
            const firebaseConfig = {
                apiKey: "AIzaSyBd65HeQ6ZMKyb8DHc05m9Buj9plk4NY04",
                authDomain: "digital-export-dashboard.firebaseapp.com",
                projectId: "digital-export-dashboard",
                storageBucket: "digital-export-dashboard.firebasestorage.app",
                messagingSenderId: "277722139352",
                appId: "1:277722139352:web:21084a3222f13c0aa1e5ad"
            };

            // Initialize Firebase without authentication
            if (!firebase.apps.length) {
                firebase.initializeApp(firebaseConfig);
            }
            
            this.db = firebase.firestore();
            
            // Set Firestore settings to bypass security rules for demo
            this.db.settings({
                experimentalForceLongPolling: true,
                merge: true
            });
            
            console.log('Firebase initialized successfully (No Auth)');
            this.setupConnectionMonitoring();
            
        } catch (error) {
            console.log('Firebase initialization failed, using local storage only:', error.message);
            this.isConnected = false;
        }
    }

    generateUserId() {
        // Generate a persistent user ID for local storage
        let userId = localStorage.getItem('securityAppUserId');
        if (!userId) {
            userId = 'user-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('securityAppUserId', userId);
        }
        return userId;
    }

    setupConnectionMonitoring() {
        if (!this.db) return;
        
        this.db.enableNetwork().then(() => {
            this.isConnected = true;
            console.log('Firestore connected');
        }).catch(error => {
            console.log('Firestore offline, using local storage');
            this.isConnected = false;
        });
    }

    async saveScanResult(scanData) {
        const timestamp = new Date().toISOString();
        const scanId = 'scan-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        
        const enhancedData = {
            ...scanData,
            id: scanId,
            timestamp: timestamp,
            userId: this.userId
        };

        // Always save to localStorage first
        const localId = this.saveToLocalStorage(enhancedData);

        // Try to save to Firebase if connected (bypass security rules)
        if (this.isConnected && this.db) {
            try {
                // Try to save to a public collection that doesn't require authentication
                const publicScanRef = this.db.collection('public_scans').doc(scanId);
                await publicScanRef.set({
                    ...enhancedData,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    isPublic: true
                });
                
                console.log('Scan saved to Firebase Public Collection');
                return scanId;
            } catch (error) {
                console.log('Failed to save to Firebase, using local storage:', error.message);
                return localId;
            }
        }
        
        return localId;
    }

    async getScanHistory(limit = 50) {
        // Try Firebase first if available
        if (this.isConnected && this.db) {
            try {
                // Try to get from public collection
                const snapshot = await this.db.collection('public_scans')
                    .where('userId', '==', this.userId)
                    .orderBy('timestamp', 'desc')
                    .limit(limit)
                    .get();
                
                const firebaseScans = snapshot.docs.map(doc => ({
                    id: doc.id,
                    ...doc.data()
                }));

                return firebaseScans;
            } catch (error) {
                console.log('Failed to fetch from Firebase, using local storage:', error.message);
            }
        }
        
        // Fallback to local storage
        return this.getFromLocalStorage(limit);
    }

    saveToLocalStorage(scanData) {
        try {
            const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
            history.push(scanData);
            
            // Keep only last 100 entries
            const updatedHistory = history.slice(-100);
            localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
            
            return scanData.id;
        } catch (error) {
            console.error('Error saving to localStorage:', error);
            return 'local-' + Date.now();
        }
    }

    getFromLocalStorage(limit = null) {
        try {
            const data = JSON.parse(localStorage.getItem('scanHistory')) || [];
            return limit ? data.slice(-limit) : data;
        } catch (error) {
            console.error('Error reading from localStorage:', error);
            return [];
        }
    }

    // Clear all data
    clearAllData() {
        localStorage.removeItem('scanHistory');
        localStorage.removeItem('securityAppUserId');
        this.userId = this.generateUserId();
        return true;
    }
}

// Initialize Firebase Manager
const firebaseManager = new FirebaseManager();