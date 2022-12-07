/*!
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import * as vscode from 'vscode'
import { CredentialsSettings } from './credentialsUtilities'
import { telemetry } from '../shared/telemetry/telemetry'
import { Auth, IamConnection, isIamConnection, toPickerItem } from './auth'
import { ToolkitError } from '../shared/errors'
import { showQuickPick } from '../shared/ui/pickerPrompter'

export class CredentialsInjector implements vscode.TerminalProfileProvider {
    readonly #disposables = [] as vscode.Disposable[]

    public constructor(
        private readonly settings: CredentialsSettings,
        private readonly collection: vscode.EnvironmentVariableCollection,
        private readonly auth = Auth.instance
    ) {
        collection.persistent = false

        this.#disposables.push(
            this.settings.onDidChange(async ({ key }) => {
                if (key === 'injectCredentials') {
                    await this.handleUpdate()
                }
            }),
            this.auth.onDidChangeActiveConnection(conn => this.handleUpdate(conn))
        )
    }

    public get enabled() {
        return this.settings.get('injectCredentials', false)
    }

    // Remaining work:
    // * handle the cancellation token
    // * move logic to a command to leverage an `onCommand` activation event
    public async provideTerminalProfile(token: vscode.CancellationToken): Promise<vscode.TerminalProfile | undefined> {
        await this.auth.tryAutoConnect()
        const conn = isIamConnection(this.auth.activeConnection)
            ? this.auth.activeConnection
            : await promptForIamConnection(this.auth)

        if (!conn || !isIamConnection(conn) || this.auth.getConnectionState(conn) !== 'valid') {
            throw new ToolkitError('No valid AWS IAM connection found.', { code: 'NoConnection' })
        }

        return new vscode.TerminalProfile({
            strictEnv: true,
            name: `AWS (${conn.label})`,
            env: await injectCredentials(conn, 'TerminalProfile'),
            message: `Using AWS connection "${conn.label}"`,
            isTransient: true,
        } as vscode.TerminalOptions)
    }

    public dispose(): void {
        vscode.Disposable.from(...this.#disposables).dispose()
        this.collection.clear()
    }

    private async handleUpdate(conn = this.auth.activeConnection) {
        // This will not work well with multiple users of `EnvironmentVariableCollection`
        this.collection.clear()
        if (!this.enabled) {
            return
        }

        if (conn?.state === 'valid' && isIamConnection(conn)) {
            await this.updateCollection(conn)
        }
    }

    private async updateCollection(conn: IamConnection): Promise<void> {
        const variables = await injectCredentials(conn, 'AutomaticInjection', {})
        for (const [k, v] of Object.entries(variables)) {
            if (v !== undefined) {
                this.collection.replace(k, v)
            } else {
                this.collection.delete(k)
            }
        }
    }
}

export async function injectCredentials(
    connection: IamConnection,
    source?: 'TerminalProfile' | 'AutomaticInjection',
    env = process.env
) {
    return telemetry.aws_injectCredentials.run(async () => {
        telemetry.record({ source, passive: true })

        const credentials = await connection.getCredentials()

        return {
            ...env,
            AWS_REGION: connection.defaultRegion,
            AWS_ACCESS_KEY_ID: credentials.accessKeyId,
            AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
            AWS_SESSION_TOKEN: credentials.sessionToken,
        }
    })
}

async function promptForIamConnection(auth: Auth) {
    const items = (async function () {
        const connections = await auth.listConnections()

        return connections.filter(isIamConnection).map(toPickerItem)
    })()

    return showQuickPick(items, {
        title: 'Select a Connection',
        placeholder: 'Select an IAM credential to use',
    })
}
