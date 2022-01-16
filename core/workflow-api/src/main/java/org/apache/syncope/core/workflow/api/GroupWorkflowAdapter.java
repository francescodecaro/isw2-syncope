/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.workflow.api;

import org.apache.syncope.common.lib.request.GroupCR;
import org.apache.syncope.common.lib.request.GroupUR;
import org.apache.syncope.core.provisioning.api.WorkflowResult;

/**
 * Interface for calling underlying workflow implementations.
 */
public interface GroupWorkflowAdapter extends WorkflowAdapter {

    /**
     * Create a group.
     *
     * @param groupCR group to be created and whether to propagate it as active
     * @param creator username that requested this operation
     * @param context context information
     * @return group just created
     */
    WorkflowResult<String> create(GroupCR groupCR, String creator, String context);

    /**
     * Update a group.
     *
     * @param groupUR modification set to be performed
     * @param updater username that requested this operation
     * @param context context information
     * @return group just updated and propagations to be performed
     */
    WorkflowResult<GroupUR> update(GroupUR groupUR, String updater, String context);

    /**
     * Delete a group.
     *
     * @param groupKey group to be deleted
     */
    void delete(String groupKey);
}
