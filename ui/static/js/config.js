// ui/static/js/config.js

document.addEventListener('DOMContentLoaded', function() {
    // Initialize configuration forms
    initConfigForms();
    
    // Initialize range sliders
    initRangeSliders();
    
    // Load current configuration
    loadConfiguration();
    
    // Add event listener for test email button
    document.getElementById('testEmailBtn').addEventListener('click', testEmailNotification);
    
    // Add event listener for reset defaults button
    document.getElementById('resetDefaultsBtn').addEventListener('click', resetToDefaults);
});

function initConfigForms() {
    // Detection Config Form
    document.getElementById('detectionConfigForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const config = {
            detection_threshold: parseFloat(document.getElementById('detectionThreshold').value),
            false_positive_threshold: parseFloat(document.getElementById('falsePositiveThreshold').value),
            batch_size: parseInt(document.getElementById('batchSize').value),
            check_interval: parseFloat(document.getElementById('checkInterval').value),
            streaming_services: document.getElementById('streamingServices').value.split(',').map(s => s.trim()),
            critical_attack_types: document.getElementById('criticalAttackTypes').value.split(',').map(s => s.trim())
        };
        
        // Save configuration
        saveConfiguration('Detection', config);
    });
    
    // Prevention Config Form
    document.getElementById('preventionConfigForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const config = {
            auto_block: document.getElementById('autoBlock').checked,
            block_duration: parseInt(document.getElementById('blockDuration').value),
            min_alerts_for_autoblock: parseInt(document.getElementById('minAlertsForAutoblock').value),
            alert_window: parseInt(document.getElementById('alertWindow').value),
            whitelist: document.getElementById('whitelist').value.split(',').map(s => s.trim()),
            autoblock_attack_types: document.getElementById('autoblockAttackTypes').value.split(',').map(s => s.trim())
        };
        
        // Save configuration
        saveConfiguration('Prevention', config);
    });
    
    // Network Config Form
    document.getElementById('networkConfigForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const config = {
            interface: document.getElementById('interface').value,
            capture_filter: document.getElementById('captureFilter').value,
            buffer_size: parseInt(document.getElementById('bufferSize').value),
            max_packets_per_flow: parseInt(document.getElementById('maxPacketsPerFlow').value),
            whitelist_ports: document.getElementById('whitelistPorts').value.split(',').map(s => s.trim())
        };
        
        // Save configuration
        saveConfiguration('Network', config);
    });
    
    // Notification Config Form
    document.getElementById('notificationConfigForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const config = {
            enable_notifications: document.getElementById('enableNotifications').checked,
            smtp_server: document.getElementById('smtpServer').value,
            smtp_port: parseInt(document.getElementById('smtpPort').value),
            sender_email: document.getElementById('senderEmail').value,
            password: document.getElementById('emailPassword').value,
            recipients: document.getElementById('recipients').value.split(',').map(s => s.trim()),
            cooldown_period: parseInt(document.getElementById('cooldownPeriod').value),
            min_confidence_for_notification: parseFloat(document.getElementById('minConfidenceForNotification').value),
            message_format: document.getElementById('messageFormat').value
        };
        
        // Save configuration
        saveConfiguration('Notification', config);
    });
    
    // Advanced Config Form
    document.getElementById('advancedConfigForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const config = {
            learning_mode: document.getElementById('learningMode').checked,
            async_analysis: document.getElementById('asyncAnalysis').checked,
            detailed_traffic_logging: document.getElementById('detailedTrafficLogging').checked,
            multi_model_analysis: document.getElementById('multiModelAnalysis').checked,
            max_analysis_threads: parseInt(document.getElementById('maxAnalysisThreads').value),
            min_packets_for_pattern_analysis: parseInt(document.getElementById('minPacketsForAnalysis').value),
            data_retention_days: parseInt(document.getElementById('dataRetentionDays').value),
            max_flow_analysis_time: parseInt(document.getElementById('maxFlowAnalysisTime').value),
            secondary_model_min_confidence: parseFloat(document.getElementById('secondaryModelMinConfidence').value),
            result_blending_mode: document.getElementById('resultBlendingMode').value,
            model_weights: document.getElementById('modelWeights').value.split(',').map(s => parseFloat(s.trim()))
        };
        
        // Save configuration
        saveConfiguration('Advanced', config);
    });
}

function initRangeSliders() {
    // Detection threshold slider
    const detectionThreshold = document.getElementById('detectionThreshold');
    const detectionThresholdValue = document.getElementById('detectionThresholdValue');
    
    detectionThreshold.addEventListener('input', function() {
        detectionThresholdValue.textContent = this.value;
    });
    
    // False positive threshold slider
    const falsePositiveThreshold = document.getElementById('falsePositiveThreshold');
    const falsePositiveThresholdValue = document.getElementById('falsePositiveThresholdValue');
    
    falsePositiveThreshold.addEventListener('input', function() {
        falsePositiveThresholdValue.textContent = this.value;
    });
    
    // Min confidence for notification slider
    const minConfidenceForNotification = document.getElementById('minConfidenceForNotification');
    const minConfidenceForNotificationValue = document.getElementById('minConfidenceForNotificationValue');
    
    minConfidenceForNotification.addEventListener('input', function() {
        minConfidenceForNotificationValue.textContent = this.value;
    });
    
    // Secondary model min confidence slider
    const secondaryModelMinConfidence = document.getElementById('secondaryModelMinConfidence');
    const secondaryModelMinConfidenceValue = document.getElementById('secondaryModelMinConfidenceValue');
    
    secondaryModelMinConfidence.addEventListener('input', function() {
        secondaryModelMinConfidenceValue.textContent = this.value;
    });
}

function loadConfiguration() {
    // Show loading indicator
    showToast('Loading configuration...', 'info');
    
    // Fetch configuration
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            // Populate detection config
            if (config.Detection) {
                document.getElementById('detectionThreshold').value = config.Detection.detection_threshold || 0.7;
                document.getElementById('detectionThresholdValue').textContent = config.Detection.detection_threshold || 0.7;
                
                document.getElementById('falsePositiveThreshold').value = config.Detection.false_positive_threshold || 0.8;
                document.getElementById('falsePositiveThresholdValue').textContent = config.Detection.false_positive_threshold || 0.8;
                
                document.getElementById('batchSize').value = config.Detection.batch_size || 10;
                document.getElementById('checkInterval').value = config.Detection.check_interval || 1.0;
                
                if (config.Detection.streaming_services) {
                    document.getElementById('streamingServices').value = Array.isArray(config.Detection.streaming_services) 
                        ? config.Detection.streaming_services.join(', ')
                        : config.Detection.streaming_services;
                }
                
                                if (config.Detection.critical_attack_types) {
                    document.getElementById('criticalAttackTypes').value = Array.isArray(config.Detection.critical_attack_types) 
                        ? config.Detection.critical_attack_types.join(', ')
                        : config.Detection.critical_attack_types;
                }
            }
            
            // Populate prevention config
            if (config.Prevention) {
                document.getElementById('autoBlock').checked = config.Prevention.auto_block === 'true';
                document.getElementById('blockDuration').value = config.Prevention.block_duration || 300;
                document.getElementById('minAlertsForAutoblock').value = config.Prevention.min_alerts_for_autoblock || 3;
                document.getElementById('alertWindow').value = config.Prevention.alert_window || 60;
                
                if (config.Prevention.whitelist) {
                    document.getElementById('whitelist').value = Array.isArray(config.Prevention.whitelist) 
                        ? config.Prevention.whitelist.join(', ')
                        : config.Prevention.whitelist;
                }
                
                if (config.Prevention.autoblock_attack_types) {
                    document.getElementById('autoblockAttackTypes').value = Array.isArray(config.Prevention.autoblock_attack_types) 
                        ? config.Prevention.autoblock_attack_types.join(', ')
                        : config.Prevention.autoblock_attack_types;
                }
            }
            
            // Populate network config
            if (config.Network) {
                document.getElementById('interface').value = config.Network.interface || 'eth0';
                document.getElementById('captureFilter').value = config.Network.capture_filter || 'ip';
                document.getElementById('bufferSize').value = config.Network.buffer_size || 1000;
                document.getElementById('maxPacketsPerFlow').value = config.Network.max_packets_per_flow || 20;
                
                if (config.Network.whitelist_ports) {
                    document.getElementById('whitelistPorts').value = Array.isArray(config.Network.whitelist_ports) 
                        ? config.Network.whitelist_ports.join(', ')
                        : config.Network.whitelist_ports;
                }
            }
            
            // Populate notification config
            if (config.Notification) {
                document.getElementById('enableNotifications').checked = config.Notification.enable_notifications === 'true';
                document.getElementById('smtpServer').value = config.Notification.smtp_server || 'smtp.gmail.com';
                document.getElementById('smtpPort').value = config.Notification.smtp_port || 587;
                document.getElementById('senderEmail').value = config.Notification.sender_email || 'your_email@gmail.com';
                document.getElementById('cooldownPeriod').value = config.Notification.cooldown_period || 300;
                
                document.getElementById('minConfidenceForNotification').value = config.Notification.min_confidence_for_notification || 0.85;
                document.getElementById('minConfidenceForNotificationValue').textContent = config.Notification.min_confidence_for_notification || 0.85;
                
                document.getElementById('messageFormat').value = config.Notification.message_format || 'html';
                
                if (config.Notification.recipients) {
                    document.getElementById('recipients').value = Array.isArray(config.Notification.recipients) 
                        ? config.Notification.recipients.join(', ')
                        : config.Notification.recipients;
                }
            }
            
            // Populate advanced config
            if (config.Advanced) {
                document.getElementById('learningMode').checked = config.Advanced.learning_mode === 'true';
                document.getElementById('asyncAnalysis').checked = config.Advanced.async_analysis === 'true';
                document.getElementById('detailedTrafficLogging').checked = config.Advanced.detailed_traffic_logging === 'true';
                document.getElementById('multiModelAnalysis').checked = config.Advanced.multi_model_analysis === 'true';
                
                document.getElementById('maxAnalysisThreads').value = config.Advanced.max_analysis_threads || 4;
                document.getElementById('minPacketsForAnalysis').value = config.Advanced.min_packets_for_pattern_analysis || 5;
                document.getElementById('dataRetentionDays').value = config.Advanced.data_retention_days || 30;
                document.getElementById('maxFlowAnalysisTime').value = config.Advanced.max_flow_analysis_time || 30;
                
                document.getElementById('secondaryModelMinConfidence').value = config.Advanced.secondary_model_min_confidence || 0.65;
                document.getElementById('secondaryModelMinConfidenceValue').textContent = config.Advanced.secondary_model_min_confidence || 0.65;
                
                document.getElementById('resultBlendingMode').value = config.Advanced.result_blending_mode || 'ensemble';
                
                if (config.Advanced.model_weights) {
                    document.getElementById('modelWeights').value = Array.isArray(config.Advanced.model_weights) 
                        ? config.Advanced.model_weights.join(', ')
                        : config.Advanced.model_weights;
                }
            }
            
            showToast('Configuration loaded successfully', 'success');
        })
        .catch(error => {
            console.error('Error loading configuration:', error);
            showToast('Error loading configuration', 'danger');
        });
}

function saveConfiguration(section, config) {
    // Show loading indicator
    showToast(`Saving ${section} configuration...`, 'info');
    
    // Prepare data
    const data = {
        section: section,
        config: config
    };
    
    // Send to server
    fetch('/api/config', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            showToast(`${section} configuration saved successfully`, 'success');
        } else {
            showToast(`Error saving ${section} configuration: ${result.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error(`Error saving ${section} configuration:`, error);
        showToast(`Error saving ${section} configuration`, 'danger');
    });
}

function testEmailNotification() {
    // Show confirmation dialog
    if (!confirm('Send a test email with current settings?')) {
        return;
    }
    
    // Collect email settings
    const settings = {
        smtp_server: document.getElementById('smtpServer').value,
        smtp_port: parseInt(document.getElementById('smtpPort').value),
        sender_email: document.getElementById('senderEmail').value,
        password: document.getElementById('emailPassword').value,
        recipients: document.getElementById('recipients').value.split(',').map(s => s.trim()),
        message_format: document.getElementById('messageFormat').value
    };
    
    // Check for required fields
    if (!settings.smtp_server || !settings.sender_email || !settings.password || settings.recipients.length === 0) {
        showToast('Please fill all required email settings', 'warning');
        return;
    }
    
    // Show loading indicator
    showToast('Sending test email...', 'info');
    
    // Send test email request
    fetch('/api/test_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(settings)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            showToast('Test email sent successfully', 'success');
        } else {
            showToast(`Error sending test email: ${result.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error sending test email:', error);
        showToast('Error sending test email', 'danger');
    });
}

function resetToDefaults() {
    // Show confirmation dialog
    if (!confirm('Reset all advanced settings to default values?')) {
        return;
    }
    
    // Reset advanced settings to defaults
    document.getElementById('learningMode').checked = false;
    document.getElementById('asyncAnalysis').checked = true;
    document.getElementById('detailedTrafficLogging').checked = false;
    document.getElementById('multiModelAnalysis').checked = true;
    
    document.getElementById('maxAnalysisThreads').value = 4;
    document.getElementById('minPacketsForAnalysis').value = 5;
    document.getElementById('dataRetentionDays').value = 30;
    document.getElementById('maxFlowAnalysisTime').value = 30;
    
    document.getElementById('secondaryModelMinConfidence').value = 0.65;
    document.getElementById('secondaryModelMinConfidenceValue').textContent = 0.65;
    
    document.getElementById('resultBlendingMode').value = 'ensemble';
    document.getElementById('modelWeights').value = '0.6, 0.4';
    
    showToast('Advanced settings reset to defaults', 'success');
}