/*!
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import { ECS } from 'aws-sdk'
import { ext } from '../extensionGlobals'
import { getLogger } from '../logger'
import { ClassToInterfaceType } from '../utilities/tsUtils'

export type EcsClient = ClassToInterfaceType<DefaultEcsClient>

export type ServicesAndToken = {
    services: ECS.Service[]
    nextToken?: string
}

export type ClustersAndToken = {
    clusters: ECS.Cluster[]
    nextToken?: string
}

const MAX_RESULTS = 50
export class DefaultEcsClient {
    public constructor(public readonly regionCode: string) {}

    public async listClusters(nextToken?: string): Promise<ClustersAndToken> {
        const sdkClient = await this.createSdkClient()
        const clusterArnList = await sdkClient.listClusters({ maxResults: MAX_RESULTS, nextToken }).promise()
        try {
            const clusterResponse = await sdkClient.describeClusters({ clusters: clusterArnList.clusterArns }).promise()
            const response: ClustersAndToken = {
                clusters: clusterResponse.clusters!,
                nextToken: clusterArnList.nextToken,
            }
            return response
        } catch (error) {
            getLogger().error('ecs: Failed to list clusters: %s', error)
            throw error
        }
    }

    public async listServices(cluster: string, nextToken?: string): Promise<ServicesAndToken> {
        const sdkClient = await this.createSdkClient()
        const serviceArnList = await sdkClient
            .listServices({ cluster: cluster, maxResults: MAX_RESULTS, nextToken })
            .promise()
        try {
            const serviceResponse = await sdkClient
                .describeServices({ services: serviceArnList.serviceArns!, cluster: cluster })
                .promise()
            const response: ServicesAndToken = {
                services: serviceResponse.services!,
                nextToken: serviceArnList.nextToken,
            }
            return response
        } catch (error) {
            getLogger().error('ecs: Failed to list services for cluster %s: %O', cluster, error)
            throw error
        }
    }

    public async listContainerNames(taskDefinition: string): Promise<string[]> {
        const sdkClient = await this.createSdkClient()
        try {
            const describeTaskDefinitionResponse = await sdkClient.describeTaskDefinition({ taskDefinition }).promise()
            const containerNames = describeTaskDefinitionResponse.taskDefinition?.containerDefinitions?.map(cd => {
                return cd.name ?? ''
            })
            return containerNames ?? []
        } catch (error) {
            getLogger().error('ecs: Failed to list containers for task definition %s: %O', taskDefinition, error)
            throw error
        }
    }

    public async listTasks(cluster: string, serviceName: string): Promise<string[]> {
        const sdkClient = await this.createSdkClient()

        const params: ECS.ListTasksRequest = { cluster: cluster, serviceName: serviceName, desiredStatus: 'RUNNING' }
        console.log(params)
        try {
            const listTasksResponse = await sdkClient.listTasks(params).promise()
            console.log(listTasksResponse)
            return listTasksResponse.taskArns ?? []
        } catch (error) {
            getLogger().error(`ecs: Failed to get tasks for Cluster ${cluster} and Service ${serviceName}: `)
            throw error
        }
    }

    protected async createSdkClient(): Promise<ECS> {
        return await ext.sdkClientBuilder.createAwsService(ECS, undefined, this.regionCode)
    }
}
