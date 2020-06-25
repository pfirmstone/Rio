/*
 * Copyright to the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rioproject.impl.system.capability

import groovy.util.logging.Log
import org.rioproject.system.capability.PlatformCapability

/**
 * Writes out a {@link PlatformCapability} to a Groovy class file
 *
 * @author Dennis Reedy
 */
@Log
class PlatformCapabilityWriter {

    /**
     * Write a PlatformCapability to a Groovy class file
     *
     * @param pCap The <tt>PlatformCapability</tt> to write
     * @param configPath Parent directory to store the generated file
     */
    static String write(PlatformCapability pCap, String configPath) {

        Map<String, Object> capabilities = pCap.getCapabilities()
        def pCapVersion = ""
        if(capabilities.get(PlatformCapability.VERSION)!=null)
            pCapVersion = capabilities.get(PlatformCapability.VERSION)

        def pCapManufacturer = ""
        if(capabilities.get(PlatformCapability.MANUFACTURER)!=null)
            pCapManufacturer = capabilities.get(PlatformCapability.MANUFACTURER)

        def pCapDescription = ""
        if(pCap.description)
            pCapDescription = pCap.description

        def classPath = ""
        if(pCap.classPath) {
            pCap.classPath.each { element ->
                classPath += element + " "
            }
        }

        if(!configPath.endsWith(File.separator))
            configPath += File.separator
        def fileName = configPath+pCap.getName().toLowerCase().replace(" ", "-")+".groovy"
        def file = new File(fileName)
        if(file.exists()) {
            log.warning("Overwriting ${file.path}")
            file.delete()
        }
        file << '/* Generated by '+System.getProperty("user.name")+' on '+new Date()+' */\n\n'
        file << 'import org.rioproject.config.PlatformCapabilityConfig\n\n'
        file << 'class '+pCap.getName()+'Config {\n\n'
        file << '    def getPlatformCapabilityConfigs() {\n'
        file << '        def configs = []\n'
        file << '        configs << new PlatformCapabilityConfig(\"'+pCap.getName()+'\",\n' +
        '                                                \"'+pCapVersion+'\",\n' +
        '                                                \"'+pCapDescription+'\",\n' +
        '                                                \"'+pCapManufacturer+'\",\n' +
        '                                                \"'+classPath+'\")\n'
        file << '        return configs\n'
        file << '    }\n'
        file << '}'

        return fileName
    }
}
