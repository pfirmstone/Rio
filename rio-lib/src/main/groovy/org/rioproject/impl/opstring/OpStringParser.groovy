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
package org.rioproject.impl.opstring
/**
 * Defines the semantics for an OperationalString parser
 *
 * @author Jerome Bernard
 * @author Dennis Reedy
 */
interface OpStringParser {

    def List<OpString> parse(source, ClassLoader loader, String[] defaultGroups, loadPath)

    @Deprecated
    def List<OpString> parse(source,
                             ClassLoader loader,
                             String[] defaultExportJars,
                             String[] defaultGroups,
                             loadPath)
}