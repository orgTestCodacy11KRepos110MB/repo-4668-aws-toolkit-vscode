/*!
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import * as vscode from 'vscode'
import { AwsContext } from '../shared/awsContext'
import { isCloud9 } from '../shared/extensionUtilities'
import { Settings } from '../shared/settings'
import { Auth } from './auth'
import { CredentialsSettings } from './credentialsUtilities'
import { CredentialsInjector } from './environment'
import { LoginManager } from './loginManager'
import { fromString } from './providers/credentials'

export async function initialize(
    extensionContext: vscode.ExtensionContext,
    awsContext: AwsContext,
    settings: Settings,
    loginManager: LoginManager
): Promise<void> {
    Auth.instance.onDidChangeActiveConnection(conn => {
        // This logic needs to be moved to `Auth.useConnection` to correctly record `passive`
        if (conn?.type === 'iam' && conn.state === 'valid') {
            loginManager.login({ passive: true, providerId: fromString(conn.id) })
        } else {
            loginManager.logout()
        }
    })

    const credentialsSettings = new CredentialsSettings(settings)
    const injector = new CredentialsInjector(credentialsSettings, extensionContext.environmentVariableCollection)

    if (!isCloud9()) {
        extensionContext.subscriptions.push(injector, vscode.window.registerTerminalProfileProvider('aws', injector))
    }
}

declare module 'vscode' {
    /**
     * Provides a terminal profile for the contributed terminal profile when launched via the UI or
     * command.
     */
    export interface TerminalProfileProvider {
        /**
         * Provide the terminal profile.
         * @param token A cancellation token that indicates the result is no longer needed.
         * @returns The terminal profile.
         */
        provideTerminalProfile(token: CancellationToken): ProviderResult<TerminalProfile>
    }

    /**
     * A terminal profile defines how a terminal will be launched.
     */
    export class TerminalProfile {
        /**
         * The options that the terminal will launch with.
         */
        options: TerminalOptions | ExtensionTerminalOptions

        /**
         * Creates a new terminal profile.
         * @param options The options that the terminal will launch with.
         */
        constructor(options: TerminalOptions | ExtensionTerminalOptions)
    }

    export namespace window {
        /**
         * Registers a provider for a contributed terminal profile.
         * @param id The ID of the contributed terminal profile.
         * @param provider The terminal profile provider.
         */
        export function registerTerminalProfileProvider(id: string, provider: TerminalProfileProvider): Disposable
    }
}
