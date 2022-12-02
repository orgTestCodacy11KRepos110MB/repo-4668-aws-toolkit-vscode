/*!
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import { Auth } from '../auth'
import { CredentialsProviderType } from './credentials'
import { BaseCredentialsProviderFactory } from './credentialsProviderFactory'
import { SsoCredentialsProvider } from './ssoCredentialsProvider'

export class SsoCredentialsProviderFactory extends BaseCredentialsProviderFactory<SsoCredentialsProvider> {
    public constructor(private readonly auth: Auth) {
        super()
    }

    public async refresh(): Promise<void> {
        this.resetProviders()

        for (const provider of this.auth.listLinkedCredentialsProviders()) {
            this.addProvider(provider)
        }
    }

    public getProviderType(): CredentialsProviderType | undefined {
        return 'sso'
    }
}
