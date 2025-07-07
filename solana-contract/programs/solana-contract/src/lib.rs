use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, MintTo, Burn};

declare_id!("4NgeNZmnDKZ5s9h1wYewjt8qz5KVSA4Yeweqs8rR49wj"); // Replace with your program ID

/// The BridgeState holds the configuration for the bridge.
#[account]
pub struct BridgeState {
    /// The authority (admin/oracle) allowed to mint wrapped tokens
    pub admin: Pubkey,
    /// The mint of the wrapped QUBIC token on Solana
    pub wqubic_mint: Pubkey,
    /// Bump seed for the PDA (if needed for signing as mint authority)
    pub bump: u8,
}

/// Events to emit on minting and burning (for off-chain relayers to monitor)
#[event]
pub struct MintEvent {
    pub to: Pubkey,
    pub amount: u64,
}
#[event]
pub struct BurnEvent {
    pub from: Pubkey,
    pub amount: u64,
}

#[program]
pub mod solana_qubic_bridge {
    use super::*;

    /// Initialize the BridgeState and create the wQUBIC token mint.
    /// This should be called once by the admin (deployer) after program deployment.
    pub fn initialize(ctx: Context<Initialize>, decimals: u8) -> Result<()> {
        // Set the bridge state fields
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.admin = ctx.accounts.admin.key();
        bridge_state.wqubic_mint = ctx.accounts.wqubic_mint.key();
        bridge_state.bump = *ctx.bumps.get("bridge_state").unwrap();  // store PDA bump

        msg!("Initializing wQUBIC mint with authority = BridgeState PDA");
        // The Anchor init macro for the mint account (in Context) will have already
        // created and initialized the mint with the specified authority and decimals.
        // So nothing more to do here besides logging.
        Ok(())
    }

    /// Mint wrapped QUBIC (wQUBIC) to a user's token account on Solana.
    /// Only the admin (bridge oracle) can call this, after seeing QUBIC locked on the other chain.
    pub fn mint_wrapped(ctx: Context<MintWrapped>, amount: u64) -> Result<()> {
        // Only allow the authorized admin to mint
        require!(
            ctx.accounts.bridge_state.admin == ctx.accounts.admin.key(),
            BridgeError::Unauthorized
        );
        // Mint the specified amount of wQUBIC to the recipient's token account
        token::mint_to(
            ctx.accounts.into_mint_to_context().with_signer(&[&[
                b"bridge-state",
                &[*ctx.bumps.get("bridge_state").unwrap()],
            ]]),
            amount,
        )?;
        // Emit event for off-chain monitoring
        emit!(MintEvent {
            to: ctx.accounts.to_account.owner, // the user receiving (owner of token account)
            amount,
        });
        msg!("Minted {} wQUBIC to {}", amount, ctx.accounts.to_account.owner);
        Ok(())
    }

    /// Burn wQUBIC from the user's token account to initiate bridging back to native QUBIC.
    /// Any user holding wQUBIC can call this to redeem their tokens (which will be released on the other chain).
    pub fn burn_wrapped(ctx: Context<BurnWrapped>, amount: u64) -> Result<()> {
        // Burn the specified amount from the user's token account.
        token::burn(
            ctx.accounts.into_burn_context(), 
            amount,
        )?;
        // Emit event for off-chain monitoring
        emit!(BurnEvent {
            from: ctx.accounts.from_account.owner, // user burning
            amount,
        });
        msg!("Burned {} wQUBIC from {}", amount, ctx.accounts.from_account.owner);
        Ok(())
    }
}

/// Accounts for initialization.
#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,  // The deployer/bridge administrator
    /// BridgeState PDA account (derivation ensures a single, global instance)
    #[account(
        init,
        payer = admin,
        seeds = [b"bridge-state"],
        bump,
        space = 8 + std::mem::size_of::<BridgeState>(),  // allocate enough space
    )]
    pub bridge_state: Account<'info, BridgeState>,
    /// wQUBIC Mint account, created as a PDA with BridgeState PDA as authority
    #[account(
        init,
        payer = admin,
        // Use Anchor's mint initializer; set mint authority to the BridgeState PDA
        mint::decimals = decimals,
        mint::authority = bridge_state.key(),
        mint::freeze_authority = bridge_state.key(),
        seeds = [b"wqubic-mint"],
        bump
    )]
    pub wqubic_mint: Account<'info, Mint>,
    /// Token program (SPL token) needed for CPI calls
    pub token_program: Program<'info, Token>,
    /// System program for creating accounts
    pub system_program: Program<'info, System>,
    /// Rent sysvar (for account rent exemption)
    pub rent: Sysvar<'info, Rent>,
}

/// Context for minting wQUBIC.
#[derive(Accounts)]
pub struct MintWrapped<'info> {
    /// The bridge state, to check authority and derive signing PDA
    #[account(
        mut,
        seeds = [b"bridge-state"],
        bump = bridge_state.bump,  // ensure we have the correct PDA
    )]
    pub bridge_state: Account<'info, BridgeState>,
    /// The admin (bridge oracle) who must sign to authorize minting
    pub admin: Signer<'info>,
    /// The wQUBIC token mint
    #[account(mut, seeds = [b"wqubic-mint"], bump)]
    pub wqubic_mint: Account<'info, Mint>,
    /// The recipient's token account to receive the minted wQUBIC
    #[account(
        mut,
        constraint = to_account.mint == wqubic_mint.key(),    // ensure it's an account for wQUBIC
        constraint = to_account.owner == recipient.key(),     // ensure it belongs to the recipient
    )]
    pub to_account: Account<'info, TokenAccount>,
    /// The recipient of the tokens (just used to validate ownership of `to_account`)
    pub recipient: UncheckedAccount<'info>,  // (could also be Signer if we require user present)
    pub token_program: Program<'info, Token>,
}
impl<'info> MintWrapped<'info> {
    // Helper to get a MintTo CPI context
    fn into_mint_to_context(&self) -> CpiContext<'_, '_, '_, 'info, MintTo<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            MintTo {
                mint: self.wqubic_mint.to_account_info(),
                to: self.to_account.to_account_info(),
                authority: self.bridge_state.to_account_info(), // PDA acting as mint authority
            },
        )
    }
}

/// Context for burning wQUBIC.
#[derive(Accounts)]
pub struct BurnWrapped<'info> {
    /// Bridge state (not heavily used here, but could be checked or used for seeds if needed)
    #[account(seeds = [b"bridge-state"], bump = bridge_state.bump)]
    pub bridge_state: Account<'info, BridgeState>,
    /// The wQUBIC token mint 
    #[account(mut, seeds = [b"wqubic-mint"], bump)]
    pub wqubic_mint: Account<'info, Mint>,
    /// The token account from which to burn wQUBIC
    #[account(
        mut,
        constraint = from_account.mint == wqubic_mint.key(),   // ensure it's wQUBIC account
        constraint = from_account.owner == user.key(),         // ensure user owns this token account
    )]
    pub from_account: Account<'info, TokenAccount>,
    /// The user who is burning their tokens (must sign)
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
impl<'info> BurnWrapped<'info> {
    // Helper to get a Burn CPI context
    fn into_burn_context(&self) -> CpiContext<'_, '_, '_, 'info, Burn<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Burn {
                mint: self.wqubic_mint.to_account_info(),
                from: self.from_account.to_account_info(),
                authority: self.user.to_account_info(), // user is burning their own tokens
            },
        )
    }
}

/// Custom errors for clarity
#[error_code]
pub enum BridgeError {
    #[msg("Unauthorized: Caller is not the bridge admin")]
    Unauthorized,
}
