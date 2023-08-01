from typing import TYPE_CHECKING
from ubinascii import hexlify

from trezor import ui, wire
from trezor.enums import ButtonRequestType
from trezor.lvglui.i18n import gettext as _, keys as i18n_keys
from trezor.lvglui.lv_colors import lv_colors

from ...constants.tt import MONO_ADDR_PER_LINE
from .common import button_request, interact, raise_if_cancelled

if TYPE_CHECKING:
    from typing import Any, Awaitable, Iterable, NoReturn, Sequence
    from ..common import PropertyType, ExceptionType


__all__ = (
    "confirm_action",
    "confirm_address",
    "confirm_text",
    "confirm_amount",
    "confirm_reset_device",
    "confirm_backup",
    "confirm_path_warning",
    "confirm_sign_identity",
    "confirm_signverify",
    "show_address",
    "show_error_and_raise",
    "show_pubkey",
    "show_success",
    "show_xpub",
    "show_warning",
    "confirm_output",
    "confirm_payment_request",
    "confirm_blob",
    "confirm_properties",
    "confirm_total",
    "confirm_joint_total",
    "confirm_metadata",
    "confirm_replacement",
    "confirm_modify_output",
    "confirm_modify_fee",
    "confirm_coinjoin",
    "show_pairing_error",
    "show_popup",
    "draw_simple_text",
    "request_passphrase_on_device",
    "require_confirm_passphrase",
    "request_pin_on_device",
    "should_show_more",
    "request_strength",
    "confirm_sol_blinding_sign",
    "confirm_sol_transfer",
    "confirm_sol_create_ata",
    "confirm_sol_token_transfer",
    "confirm_sol_memo",
    "confirm_data",
    "confirm_final",
    "confirm_blind_sign_common",
    "show_onekey_app_guide",
    "confirm_set_homescreen",
    "confirm_del_wallpaper",
    "confirm_update_res",
    "confirm_domain",
    "request_pin_tips",
    "confirm_remove_nft",
    "confirm_collect_nft",
    "show_bip39_dotmap",
    "confirm_sign_typed_hash",
    "confirm_polkadot_balances",
)


async def confirm_action(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    action: str | None = None,
    description: str | None = None,
    description_param: str | None = None,
    description_param_font: int = ui.BOLD,
    verb: str | None = None,
    verb_cancel: str | None = None,
    hold: bool = False,
    hold_danger: bool = False,
    icon: str | None = "A:/res/warning.png",  # TODO cleanup @ redesign
    icon_color: int | None = None,  # TODO cleanup @ redesign
    reverse: bool = False,  # TODO cleanup @ redesign
    larger_vspace: bool = False,  # TODO cleanup @ redesign
    exc: ExceptionType = wire.ActionCancelled,
    br_code: ButtonRequestType = ButtonRequestType.Other,
    anim_dir: int = 1,
    hold_level: int = 0,
    primary_color=lv_colors.ONEKEY_GREEN,
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow

    if description and description_param is not None:
        description = description.format(description_param)
    confirm_screen = FullSizeWindow(
        title,
        f"{description or ''}{' ' + (action or '')}",
        verb if verb else _(i18n_keys.BUTTON__CONFIRM),
        cancel_text=verb_cancel
        if verb_cancel
        else _(i18n_keys.BUTTON__REJECT)
        if hold
        else _(i18n_keys.BUTTON__CANCEL),
        icon_path=icon,
        hold_confirm=hold,
        anim_dir=anim_dir,
        primary_color=primary_color,
    )
    if hold_level:
        confirm_screen.slider.change_knob_style(hold_level)
    await raise_if_cancelled(
        interact(ctx, confirm_screen, br_type, br_code),
        exc,
    )
    if anim_dir == 2:
        from trezor import loop

        await loop.sleep(300)


async def confirm_reset_device(
    ctx: wire.GenericContext, prompt: str, recovery: bool = False
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow

    if recovery:
        title = _(i18n_keys.TITLE__IMPORT_WALLET)
        # icon = "A:/res/recovery.png"
    else:
        title = _(i18n_keys.TITLE__CREATE_NEW_WALLET)
        # icon = "A:/res/add.png"
    confirm_text = _(i18n_keys.BUTTON__CONTINUE)
    cancel_text = _(i18n_keys.BUTTON__CANCEL)
    restscreen = FullSizeWindow(
        title, prompt, confirm_text, cancel_text, icon_path=None, anim_dir=0
    )
    await raise_if_cancelled(
        interact(
            ctx,
            restscreen,
            "recover_device" if recovery else "setup_device",
            ButtonRequestType.ProtectCall
            if recovery
            else ButtonRequestType.ResetDevice,
        )
    )


async def request_strength() -> int:
    from trezor.lvglui.scrs.recovery_device import SelectWordCounter

    word_cnt_strength_map = {
        12: 128,
        18: 192,
        24: 256,
    }
    screen = SelectWordCounter(_(i18n_keys.TITLE__READY_TO_CREATE))
    word_cnt = await screen.request()
    if not word_cnt:
        raise wire.ActionCancelled()
    return word_cnt_strength_map[word_cnt]


async def confirm_wipe_device(ctx: wire.GenericContext):
    from trezor.lvglui.scrs.wipe_device import WipeDevice

    confirm_screen = WipeDevice()
    await raise_if_cancelled(
        interact(ctx, confirm_screen, "wipe_device", ButtonRequestType.WipeDevice)
    )


async def confirm_wipe_device_tips(ctx: wire.GenericContext):
    from trezor.lvglui.scrs.wipe_device import WipeDeviceTips

    confirm_screen = WipeDeviceTips()
    await raise_if_cancelled(
        interact(ctx, confirm_screen, "wipe_device", ButtonRequestType.WipeDevice)
    )


async def confirm_wipe_device_success(ctx: wire.GenericContext):
    from trezor.lvglui.scrs.wipe_device import WipeDeviceSuccess

    confirm_screen = WipeDeviceSuccess()
    return await interact(
        ctx, confirm_screen, "wipe_device", ButtonRequestType.WipeDevice
    )


# TODO cleanup @ redesign
async def confirm_backup(ctx: wire.GenericContext) -> bool:
    from trezor.lvglui.scrs.common import FullSizeWindow

    title = _(i18n_keys.TITLE__WALLET_IS_READY)
    subtitle = _(i18n_keys.SUBTITLE__DEVICE_SETUP_WALLET_IS_READY)
    confirm_text = _(i18n_keys.BUTTON__CONTINUE)
    cancel_text = _(i18n_keys.BUTTON__SKIP)
    icon = "A:/res/success.png"
    if ctx == wire.DUMMY_CONTEXT:
        cancel_text = ""
    screen = FullSizeWindow(title, subtitle, confirm_text, cancel_text, icon_path=icon)
    confirmed = await interact(
        ctx,
        screen,
        "backup_device",
        ButtonRequestType.ResetDevice,
    )
    if confirmed:
        return True

    title = _(i18n_keys.TITLE__WARNING)
    subtitle = _(i18n_keys.SUBTITLE__DEVICE_SETUP_SKIP_BACK_UP_WARNING)
    icon = "A:/res/warning.png"
    screen = FullSizeWindow(title, subtitle, confirm_text, cancel_text, icon_path=icon)
    confirmed = await interact(
        ctx,
        screen,
        "backup_device",
        ButtonRequestType.ResetDevice,
    )
    return bool(confirmed)


async def confirm_path_warning(
    ctx: wire.GenericContext, path: str, path_type: str = "Path"
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow

    screen = FullSizeWindow(
        _(i18n_keys.TITLE__UNKNOWN_PATH),
        _(i18n_keys.SUBTITLE__BTC_GET_ADDRESS_UNKNOWN_PATH).format(path),
        _(i18n_keys.BUTTON__CONFIRM),
        _(i18n_keys.BUTTON__CANCEL),
        icon_path="A:/res/warning.png",
    )
    screen.btn_yes.enable(bg_color=lv_colors.ONEKEY_YELLOW, text_color=lv_colors.BLACK)
    await raise_if_cancelled(
        interact(
            ctx,
            screen,
            "path_warning",
            ButtonRequestType.UnknownDerivationPath,
        )
    )


async def show_xpub(
    ctx: wire.GenericContext,
    xpub: str,
    title: str = "",
    cancel: str = "",
    path: str = "",
    network: str = "BTC",
) -> None:
    from trezor.lvglui.scrs.template import XpubOrPub

    await raise_if_cancelled(
        interact(
            ctx,
            XpubOrPub(
                _(i18n_keys.TITLE__STR_PUBLIC_KEY).format(network),
                path=path,
                primary_color=ctx.primary_color,
                icon_path=ctx.icon_path,
                xpub=xpub,
            ),
            "show_pubkey",
            ButtonRequestType.PublicKey,
        )
    )


async def show_address(
    ctx: wire.GenericContext,
    address: str,
    *,
    address_qr: str | None = None,
    case_sensitive: bool = True,
    address_n: str | None,
    network: str = "",
    multisig_index: int | None = None,
    xpubs: Sequence[str] = (),
    address_extra: str | None = None,
    title_qr: str | None = None,
    evm_chain_id: int | None = None,
    title: str = "",
    addr_type: str | None = None,
) -> None:
    is_multisig = len(xpubs) > 0
    from trezor.lvglui.scrs.template import Address

    if is_multisig:
        return await interact(
            ctx,
            Address(
                title,
                address_n,
                address,
                ctx.primary_color,
                ctx.icon_path,
                xpubs,
                address_qr,
                multisig_index,
            ),
            "show_address",
            ButtonRequestType.Address,
        )
    await interact(
        ctx,
        Address(
            title if title else _(i18n_keys.TITLE__STR_ADDRESS).format(network),
            address_n,
            address,
            ctx.primary_color,
            ctx.icon_path,
            address_qr=address_qr,
            addr_type=addr_type,
            evm_chain_id=evm_chain_id,
        ),
        "show_address",
        ButtonRequestType.Address,
    )
    from trezor import loop

    await loop.sleep(300)


async def show_pubkey(
    ctx: wire.Context,
    pubkey: str,
    title: str = "Confirm public key",
    network: str = "ETH",
    path: str = "",
) -> None:
    from trezor.lvglui.scrs.template import XpubOrPub

    await raise_if_cancelled(
        interact(
            ctx,
            XpubOrPub(
                _(i18n_keys.TITLE__STR_PUBLIC_KEY).format(network),
                path=path,
                pubkey=pubkey,
                primary_color=ctx.primary_color,
                icon_path=ctx.icon_path,
            ),
            "show_pubkey",
            ButtonRequestType.PublicKey,
        )
    )


async def _show_modal(
    ctx: wire.GenericContext,
    br_type: str,
    br_code: ButtonRequestType,
    header: str,
    subheader: str | None,
    content: str,
    button_confirm: str | None,
    button_cancel: str | None,
    icon: str,
    icon_color: int,
    btn_yes_bg_color=None,
    exc: ExceptionType = wire.ActionCancelled,
) -> None:
    from trezor.lvglui.scrs.template import Modal

    screen = Modal(
        header,
        content,
        confirm_text=button_confirm,
        cancel_text=button_cancel,
        icon_path=icon,
    )
    if btn_yes_bg_color:
        screen.btn_yes.enable(bg_color=btn_yes_bg_color or lv_colors.ONEKEY_GREEN)
    await raise_if_cancelled(
        interact(
            ctx,
            screen,
            br_type,
            br_code,
        ),
        exc,
    )


async def show_error_and_raise(
    ctx: wire.GenericContext,
    br_type: str,
    content: str,
    header: str = "Error",
    subheader: str | None = None,
    button: str | None = None,
    red: bool = False,
    exc: ExceptionType = wire.ActionCancelled,
) -> NoReturn:
    await _show_modal(
        ctx,
        br_type=br_type,
        br_code=ButtonRequestType.Other,
        header=header,
        subheader=subheader,
        content=content,
        button_confirm=None,
        button_cancel=button if button else _(i18n_keys.BUTTON__CLOSE),
        icon="A:/res/danger.png",
        icon_color=ui.RED if red else ui.ORANGE_ICON,
        exc=exc,
    )
    raise exc


def show_warning(
    ctx: wire.GenericContext,
    br_type: str,
    content: str,
    header: str = "Warning",
    subheader: str | None = None,
    button: str = "Try again",
    br_code: ButtonRequestType = ButtonRequestType.Warning,
    icon: str = "A:/res/warning.png",
    icon_color: int = ui.RED,
    btn_yes_bg_color=None,
) -> Awaitable[None]:
    return _show_modal(
        ctx,
        br_type=br_type,
        br_code=br_code,
        header=header,
        subheader=subheader,
        content=content,
        button_confirm=_(i18n_keys.BUTTON__TRY_AGAIN),
        button_cancel=None,
        icon=icon,
        icon_color=icon_color,
        btn_yes_bg_color=btn_yes_bg_color,
    )


def show_success(
    ctx: wire.GenericContext,
    br_type: str,
    content: str,
    header: str = "Success",
    subheader: str | None = None,
    button: str = "Done",
) -> Awaitable[None]:
    return _show_modal(
        ctx,
        br_type=br_type,
        br_code=ButtonRequestType.Success,
        header=header,
        subheader=subheader,
        content=content,
        button_confirm=button,
        button_cancel=None,
        icon="A:/res/success.png",
        icon_color=ui.GREEN,
    )


async def confirm_output(
    ctx: wire.GenericContext,
    address: str,
    amount: str,
    font_amount: int = ui.NORMAL,  # TODO cleanup @ redesign
    title: str = "Confirm Transaction",
    subtitle: str | None = None,
    color_to: int = ui.FG,  # TODO cleanup @ redesign
    to_str: str = " to\n",  # TODO cleanup @ redesign
    to_paginated: bool = False,  # TODO cleanup @ redesign
    width: int = MONO_ADDR_PER_LINE,
    width_paginated: int = MONO_ADDR_PER_LINE - 1,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
    icon: str = ui.ICON_SEND,
) -> None:
    from trezor.lvglui.scrs.template import TransactionOverview

    await raise_if_cancelled(
        interact(
            ctx,
            TransactionOverview(
                _(i18n_keys.TITLE__VIEW_TRANSACTION)
                if subtitle is None
                else _(i18n_keys.TITLE__STR_TRANSACTION).format(subtitle),
                amount,
                address,
                primary_color=ctx.primary_color,
                icon_path=ctx.icon_path,
            ),
            "confirm_output",
            br_code,
        )
    )


async def confirm_payment_request(
    ctx: wire.GenericContext,
    recipient_name: str,
    amount: str,
    memos: list[str],
    coin_shortcut: str,
) -> Any:
    from trezor.lvglui.scrs.template import ConfirmPaymentRequest

    subtitle = " ".join(memos)
    screen = ConfirmPaymentRequest(
        _(i18n_keys.TITLE__CONFIRM_PAYMENT).format(coin_shortcut),
        subtitle,
        amount,
        recipient_name,
        primary_color=ctx.primary_color,
    )
    return await raise_if_cancelled(
        interact(
            ctx, screen, "confirm_payment_request", ButtonRequestType.ConfirmOutput
        )
    )


async def should_show_more(
    ctx: wire.GenericContext,
    title: str,
    para: Iterable[tuple[int, str]],
    button_text: str = "Show all",
    br_type: str = "should_show_more",
    br_code: ButtonRequestType = ButtonRequestType.Other,
    icon: str = ui.ICON_DEFAULT,
    icon_color: int = ui.ORANGE_ICON,
) -> bool:
    """Return True always because we have larger screen"""
    from trezor.lvglui.scrs.template import ShouldShowMore
    from .common import CONFIRM, SHOW_MORE

    contents = []
    for _i, text in para:
        contents.append(text)
    show_more = ShouldShowMore(
        title,
        contents[0],
        "\n".join(contents[1:]),
        button_text,
        primary_color=ctx.primary_color,
    )
    result = await raise_if_cancelled(interact(ctx, show_more, br_type, br_code))
    assert result in (CONFIRM, SHOW_MORE)

    return result == SHOW_MORE


async def confirm_blob(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    data: bytes | str,
    description: str | None = None,
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.Other,
    icon: str | None = "A:/res/warning.png",  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
    ask_pagination: bool = False,
) -> None:
    """Confirm data blob.

    Applicable for public keys, signatures, hashes. In general, any kind of
    data that is not human-readable, and can be wrapped at any character.

    For addresses, use `confirm_address`.

    Displays in monospace font. Paginates automatically.
    If data is provided as bytes or bytearray, it is converted to hex.
    """
    from trezor.lvglui.scrs.template import BlobDisPlay

    if isinstance(data, (bytes, bytearray)):
        data_str = hexlify(data).decode()
    else:
        data_str = data
    blob = BlobDisPlay(
        title,
        description if description is not None else "",
        data_str,
        icon_path=icon,
        primary_color=ctx.primary_color,
    )
    return await raise_if_cancelled(interact(ctx, blob, br_type, br_code))


async def confirm_data(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    data: bytes | str,
    description: str | None = None,
    br_code: ButtonRequestType = ButtonRequestType.Other,
) -> None:
    from trezor.lvglui.scrs.template import ContractDataOverview

    if isinstance(data, (bytes, bytearray)):
        data_str = "0x" + hexlify(data).decode()
    else:
        data_str = data
    return await raise_if_cancelled(
        interact(
            ctx,
            ContractDataOverview(
                title, description, data_str, primary_color=ctx.primary_color
            ),
            br_type,
            br_code,
        )
    )


def confirm_address(
    ctx: wire.GenericContext,
    title: str,
    address: str,
    description: str | None = "Address:",
    br_type: str = "confirm_address",
    br_code: ButtonRequestType = ButtonRequestType.Other,
    icon: str = ui.ICON_SEND,  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
) -> Awaitable[None]:
    # TODO clarify API - this should be pretty limited to support mainly confirming
    # destinations and similar
    return confirm_blob(
        ctx,
        br_type=br_type,
        title=title,
        data=address,
        description=description,
        br_code=br_code,
        icon=icon,
        icon_color=icon_color,
    )


async def confirm_text(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    data: str,
    description: str | None = None,
    br_code: ButtonRequestType = ButtonRequestType.Other,
    icon: str | None = "A:/res/warning.png",  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
) -> None:
    """Confirm textual data.

    Applicable for human-readable strings, numbers, date/time values etc.

    For amounts, use `confirm_amount`.

    Displays in bold font. Paginates automatically.
    """
    from trezor.lvglui.scrs.template import BlobDisPlay

    screen = BlobDisPlay(
        title, description, data, icon_path=icon, primary_color=ctx.primary_color
    )
    await raise_if_cancelled(interact(ctx, screen, br_type, br_code))


def confirm_amount(
    ctx: wire.GenericContext,
    title: str,
    amount: str,
    description: str = "Amount:",
    br_type: str = "confirm_amount",
    br_code: ButtonRequestType = ButtonRequestType.Other,
    icon: str = ui.ICON_SEND,  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
) -> Awaitable[None]:
    """Confirm amount."""
    # TODO clarify API - this should be pretty limited to support mainly confirming
    # destinations and similar
    return confirm_text(
        ctx,
        br_type=br_type,
        title=title,
        data=amount,
        description=_(i18n_keys.LIST_KEY__AMOUNT__COLON),
        br_code=br_code,
        icon=icon,
        icon_color=icon_color,
    )


# TODO keep name and value on the same page if possible
async def confirm_properties(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    props: Iterable[PropertyType],
    icon: str = ui.ICON_SEND,  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
) -> None:
    para = []
    from trezor.lvglui.scrs.template import ConfirmProperties

    for key, val in props:
        if key and val:
            if isinstance(val, str):
                para.append((key, val))
            elif isinstance(val, bytes):
                para.append((key, hexlify(val).decode()))
    screen = ConfirmProperties(title, para, ctx.primary_color)
    await raise_if_cancelled(interact(ctx, screen, br_type, br_code))


async def confirm_total(
    ctx: wire.GenericContext,
    total_amount: str,
    fee_amount: str,
    title: str = "Confirm transaction",
    total_label: str = "Total amount:\n",
    fee_label: str = "\nincluding fee:\n",
    icon_color: int = ui.GREEN,
    br_type: str = "confirm_total",
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
    amount: str | None = None,
    coin_shortcut: str = "BTC",
    fee_rate_amount: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import TransactionDetailsBTC

    screen = TransactionDetailsBTC(
        _(i18n_keys.TITLE__SIGN_STR_TRANSACTION).format(coin_shortcut),
        amount,
        fee_amount,
        total_amount,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(interact(ctx, screen, br_type, br_code))


async def confirm_joint_total(
    ctx: wire.GenericContext,
    spending_amount: str,
    total_amount: str,
    coin_shortcut: str = "BTC",
) -> None:
    from trezor.lvglui.scrs.template import JointTransactionDetailsBTC

    screen = JointTransactionDetailsBTC(
        _(i18n_keys.TITLE__SIGN_STR_JOINT_TX).format(coin_shortcut),
        spending_amount,
        total_amount,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_joint_total", ButtonRequestType.SignTx)
    )


async def confirm_metadata(
    ctx: wire.GenericContext,
    br_type: str,
    title: str,
    content: str,
    param: str | None = None,
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
    description: str | None = None,
    hide_continue: bool = False,
    hold: bool = False,
    param_font: int = ui.BOLD,
    icon: str = ui.ICON_SEND,  # TODO cleanup @ redesign
    icon_color: int = ui.GREEN,  # TODO cleanup @ redesign
    larger_vspace: bool = False,  # TODO cleanup @ redesign
) -> None:
    from trezor.lvglui.scrs.template import ConfirmMetaData

    has_icon_path = hasattr(ctx, "icon_path")
    confirm = ConfirmMetaData(
        title,
        content,
        description,
        param,
        ctx.primary_color,
        ctx.icon_path if has_icon_path is True else None,
    )
    await raise_if_cancelled(interact(ctx, confirm, br_type, br_code))


async def confirm_replacement(
    ctx: wire.GenericContext, description: str, txid: str
) -> None:
    from trezor.lvglui.scrs.template import ConfirmReplacement

    screen = ConfirmReplacement(description, txid, ctx.primary_color)
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_replacement", ButtonRequestType.SignTx)
    )


async def confirm_modify_output(
    ctx: wire.GenericContext,
    address: str,
    sign: int,
    amount_change: str,
    amount_new: str,
) -> None:
    if sign < 0:
        description = _(i18n_keys.LIST_KEY__INCREASED_BY__COLON)
    else:
        description = _(i18n_keys.LIST_KEY__DECREASED_BY__COLON)
    from trezor.lvglui.scrs.template import ModifyOutput

    screen = ModifyOutput(
        address, description, amount_change, amount_new, primary_Color=ctx.primary_color
    )
    await raise_if_cancelled(
        interact(
            ctx,
            screen,
            "modify_output",
            ButtonRequestType.ConfirmOutput,
        )
    )


async def confirm_modify_fee(
    ctx: wire.GenericContext,
    sign: int,
    user_fee_change: str,
    total_fee_new: str,
    fee_rate_amount: str | None = None,
) -> None:
    if sign == 0:
        description = _(i18n_keys.LIST_KEY__NO_CHANGE__COLON)
    else:
        if sign < 0:
            description = _(i18n_keys.LIST_KEY__DECREASED_BY__COLON)
        else:
            description = _(i18n_keys.LIST_KEY__INCREASED_BY__COLON)

    from trezor.lvglui.scrs.template import ModifyFee

    screen = ModifyFee(description, user_fee_change, total_fee_new, ctx.primary_color)
    await raise_if_cancelled(
        interact(ctx, screen, "modify_fee", ButtonRequestType.SignTx)
    )


async def confirm_coinjoin(
    ctx: wire.GenericContext, coin_name: str, max_rounds: int, max_fee_per_vbyte: str
) -> None:
    title = _(i18n_keys.TITLE__AUTHORIZE_COINJOIN)
    from trezor.lvglui.scrs.template import ConfirmCoinJoin

    screen = ConfirmCoinJoin(
        title,
        coin_name,
        str(max_rounds),
        max_fee_per_vbyte,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "coinjoin_final", ButtonRequestType.Other)
    )


# TODO cleanup @ redesign
async def confirm_sign_identity(
    ctx: wire.GenericContext, proto: str, identity: str, challenge_visual: str | None
) -> None:
    from trezor.lvglui.scrs.template import ConfirmSignIdentity

    screen = ConfirmSignIdentity(
        f"Sign {proto}",
        identity,
        subtitle=challenge_visual,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "sign_identity", ButtonRequestType.Other)
    )


async def confirm_signverify(
    ctx: wire.GenericContext,
    coin: str,
    message: str,
    address: str,
    verify: bool,
    evm_chain_id: int | None = None,
) -> None:
    if verify:
        header = _(i18n_keys.TITLE__VERIFY_STR_MESSAGE).format(coin)
        br_type = "verify_message"
    else:
        header = _(i18n_keys.TITLE__SIGN_STR_MESSAGE).format(coin)
        br_type = "sign_message"
    from trezor.lvglui.scrs.template import Message

    await raise_if_cancelled(
        interact(
            ctx,
            Message(
                header,
                address,
                message,
                ctx.primary_color,
                ctx.icon_path,
                verify,
                evm_chain_id,
            ),
            br_type,
            ButtonRequestType.Other,
        )
    )


async def show_popup(
    title: str,
    description: str | None = None,
    subtitle: str | None = None,
    description_param: str = "",
    timeout_ms: int = 3000,
    icon: str | None = None,
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow
    from trezor import loop

    if description and description_param:
        description = description.format(description_param)
    subtitle = f"{subtitle or ''} {description or ''}"
    FullSizeWindow(
        title, subtitle, icon_path=icon, auto_close_ms=timeout_ms, anim_dir=0
    )
    await loop.sleep(500)


def draw_simple_text(
    title: str,
    description: str = "",
    icon_path: str | None = "A:/res/warning.png",
    auto_close_ms: int = 2000,
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow

    FullSizeWindow(
        title, description, icon_path=icon_path, auto_close_ms=auto_close_ms, anim_dir=0
    )


async def request_passphrase_on_device(ctx: wire.GenericContext, max_len: int) -> str:
    await button_request(
        ctx, "passphrase_device", code=ButtonRequestType.PassphraseEntry
    )
    from trezor.lvglui.scrs.passphrase import PassphraseRequest

    screen = PassphraseRequest(max_len)
    result = await ctx.wait(screen.request())
    if result is None:
        raise wire.ActionCancelled("Passphrase entry cancelled")

    assert isinstance(result, str)

    await require_confirm_passphrase(ctx, result)
    return result


async def require_confirm_passphrase(ctx: wire.GenericContext, passphrase: str) -> None:
    from trezor.lvglui.scrs.template import PassphraseDisplayConfirm

    screen = PassphraseDisplayConfirm(passphrase)
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_passphrase", ButtonRequestType.ProtectCall)
    )


async def request_pin_on_device(
    ctx: wire.GenericContext,
    prompt: str,
    attempts_remaining: int | None,
    allow_cancel: bool,
) -> str:
    await button_request(ctx, "pin_device", code=ButtonRequestType.PinEntry)
    from storage import device

    if attempts_remaining is None or attempts_remaining == device.PIN_MAX_ATTEMPTS:
        subprompt = ""
    elif attempts_remaining == 1:
        subprompt = f"{_(i18n_keys.MSG__INCORRECT_PIN_THIS_IS_YOUR_LAST_ATTEMPT)}"
    else:
        subprompt = f"{_(i18n_keys.MSG__INCORRECT_PIN_STR_ATTEMPTS_LEFT).format(attempts_remaining)}"
    from trezor.lvglui.scrs.pinscreen import InputPin

    pinscreen = InputPin(title=prompt, subtitle=subprompt)
    result = await ctx.wait(pinscreen.request())
    if not result:
        if not allow_cancel:
            from trezor import loop

            loop.clear()
        raise wire.PinCancelled
    assert isinstance(result, str)
    return result


async def request_pin_tips(ctx: wire.GenericContext) -> None:
    from trezor.lvglui.scrs.pinscreen import PinTip

    tipscreen = PinTip()
    await raise_if_cancelled(
        interact(ctx, tipscreen, "set_pin", ButtonRequestType.Other)
    )


async def show_pairing_error() -> None:
    await show_popup(
        _(i18n_keys.TITLE__PAIR_FAILED),
        description=None,
        subtitle=_(i18n_keys.SUBTITLE__BLUETOOTH_PAIR_PAIR_FAILED),
        timeout_ms=2000,
        icon="A:/res/danger.png",
    )


async def confirm_domain(ctx: wire.GenericContext, **kwargs) -> None:
    from trezor.lvglui.scrs.template import EIP712DOMAIN

    screen = EIP712DOMAIN(
        _(i18n_keys.TITLE__STR_TYPED_DATA).format(ctx.name),
        primary_color=ctx.primary_color,
        icon_path=ctx.icon_path,
        **kwargs,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_domain", ButtonRequestType.ProtectCall)
    )


async def confirm_security_check(ctx: wire.GenericContext) -> None:
    from trezor.lvglui.scrs.template import SecurityCheck

    screen = SecurityCheck()
    await raise_if_cancelled(
        interact(ctx, screen, "security_check", ButtonRequestType.ProtectCall)
    )


async def confirm_sol_blinding_sign(
    ctx: wire.GenericContext, fee_payer: str, message_hex: str
) -> None:
    from trezor.lvglui.scrs.template import SolBlindingSign

    screen = SolBlindingSign(fee_payer, message_hex, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "sol_blinding_sign", ButtonRequestType.ProtectCall)
    )


async def confirm_sol_transfer(
    ctx: wire.GenericContext, from_addr: str, to_addr: str, fee_payer: str, amount: str
) -> None:
    from trezor.lvglui.scrs.template import SolTransfer

    screen = SolTransfer(
        from_addr=from_addr,
        to_addr=to_addr,
        fee_payer=fee_payer,
        amount=amount,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "sol_transfer", ButtonRequestType.ProtectCall)
    )


async def confirm_sol_create_ata(
    ctx: wire.GenericContext,
    fee_payer: str,
    funding_account: str,
    associated_token_account: str,
    wallet_address: str,
    token_mint: str,
):
    from trezor.lvglui.scrs.template import SolCreateAssociatedTokenAccount

    screen = SolCreateAssociatedTokenAccount(
        fee_payer,
        funding_account,
        associated_token_account,
        wallet_address,
        token_mint,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "sol_create_ata", ButtonRequestType.ProtectCall)
    )


async def confirm_sol_token_transfer(
    ctx: wire.GenericContext,
    from_addr: str,
    to_addr: str,
    amount: str,
    source_owner: str,
    fee_payer: str,
    token_mint: str = None,
):
    from trezor.lvglui.scrs.template import SolTokenTransfer

    screen = SolTokenTransfer(
        from_addr,
        to_addr,
        amount,
        source_owner,
        fee_payer,
        primary_color=ctx.primary_color,
        token_mint=token_mint,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "sol_token_transfer", ButtonRequestType.ProtectCall)
    )


async def confirm_sol_memo(
    ctx: wire.GenericContext, title: str, description: str, memo: str
) -> None:
    from trezor.lvglui.scrs.template import BlobDisPlay

    screen = BlobDisPlay(title, description, memo, None)
    await raise_if_cancelled(
        interact(ctx, screen, "sol_memo", ButtonRequestType.ProtectCall)
    )


async def confirm_final(ctx: wire.Context) -> None:
    from trezor.ui.layouts.lvgl import confirm_action

    await confirm_action(
        ctx,
        "confirm_final",
        title=_(i18n_keys.TITLE__CONFIRM_TRANSACTION),
        action=_(i18n_keys.SUBTITLE__DO_YOU_WANT_TO_SIGN__THIS_TX),
        verb=_(i18n_keys.BUTTON__SLIDE_TO_SIGN),
        hold=True,
        anim_dir=0,
        icon=None,
    )
    await show_popup(
        _(i18n_keys.TITLE__TRANSACTION_SIGNED),
        icon="A:/res/success.png",
        timeout_ms=2000,
    )


async def confirm_blind_sign_common(
    ctx: wire.Context, signer: str, raw_message: bytes
) -> None:

    from trezor.lvglui.scrs.template import BlindingSignCommon

    screen = BlindingSignCommon(signer, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "common_blinding_sign", ButtonRequestType.ProtectCall)
    )
    data_size = len(raw_message)
    await confirm_data(
        ctx,
        "confirm_data",
        title=_(i18n_keys.TITLE__VIEW_DATA),
        description=_(i18n_keys.SUBTITLE__STR_BYTES).format(data_size),
        data=raw_message,
        br_code=ButtonRequestType.SignTx,
    )


async def show_onekey_app_guide():
    if not __debug__:
        from trezor.lvglui.scrs import app_guide

        app_guide.GuideAppDownload()
        await app_guide.request()

        from apps.base import set_homescreen

        set_homescreen()


async def confirm_set_homescreen(ctx, replace: bool = False):
    await confirm_action(
        ctx=ctx,
        br_type="confirm_homescreen",
        title=_(i18n_keys.TITLE__SET_AS_HOMESCREEN),
        description=_(i18n_keys.SUBTITLE__SET_AS_HOMESCREEN)
        if not replace
        else _(i18n_keys.SUBTITLE__SET_HOMESCREEN_AND_DELETE),
        icon=None,
        anim_dir=2,
    )


async def confirm_collect_nft(ctx, replace: bool = False):
    await confirm_action(
        ctx=ctx,
        br_type="confirm_collect_nft",
        title=_(i18n_keys.TITLE__COLLECT_NFT),
        description=_(i18n_keys.SUBTITLE__COLLECT_NFT)
        if not replace
        else _(i18n_keys.SUBTITLE__COLLECT_NFT_AND_DELETE),
        icon=None,
        anim_dir=2,
    )


async def confirm_update_res(ctx, update_boot: bool = False):
    from trezor.lvglui.scrs.template import Modal

    confirm_screen = Modal(
        title=_(i18n_keys.TITLE__BOOTLOADER_UPDATE)
        if update_boot
        else _(i18n_keys.TITLE__RESOURCE_UPDATE),
        subtitle=_(i18n_keys.SUBTITLE__BOOTLOADER_UPDATE)
        if update_boot
        else _(i18n_keys.SUBTITLE__RESOURCE_UPDATE),
        confirm_text=_(i18n_keys.BUTTON__UPDATE),
        cancel_text=_(i18n_keys.BUTTON__CANCEL),
        anim_dir=2,
    )
    await raise_if_cancelled(interact(ctx, confirm_screen, "confirm_update_res"))


async def confirm_del_wallpaper(ctx, confirm_callback):
    from trezor.lvglui.scrs.common import FullSizeWindow

    confirm_screen = FullSizeWindow(
        title=_(i18n_keys.TITLE__DELETE_WALLPAPER),
        subtitle=_(i18n_keys.SUBTITLE__DELETE_WALLPAPER),
        confirm_text=_(i18n_keys.BUTTON__DELETE),
        cancel_text=_(i18n_keys.BUTTON__CANCEL),
    )
    confirm_screen.btn_yes.enable(
        bg_color=lv_colors.ONEKEY_RED_1, text_color=lv_colors.BLACK
    )
    confirm = await ctx.wait(confirm_screen.request())
    if confirm:
        confirm_callback()


async def confirm_remove_nft(ctx, confirm_callback, icon_path):
    from trezor.lvglui.scrs.template import NftRemoveConfirm

    confirm_screen = NftRemoveConfirm(icon_path)
    confirm = await ctx.wait(confirm_screen.request())
    if confirm:
        confirm_callback()


async def confirm_algo_payment(
    ctx: wire.GenericContext,
    sender: str | None = None,
    receiver: str | None = None,
    close_to: str | None = None,
    rekey_to: str | None = None,
    genesis_id: str | None = None,
    note: str | None = None,
    fee: str = 0,
    amount: str = 0,
) -> None:
    from trezor.lvglui.scrs.template import AlgoPayment, AlgoCommon

    screen = AlgoCommon("Payment", ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_payment", ButtonRequestType.ProtectCall)
    )
    screen = AlgoPayment(
        sender,
        receiver,
        close_to,
        rekey_to,
        genesis_id,
        note,
        fee,
        amount,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_payment", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_asset_freeze(
    ctx: wire.GenericContext,
    sender: str | None = None,
    rekey_to: str | None = None,
    fee: str = 0,
    index: str = 0,
    target: str | None = None,
    new_freeze_state: bool = None,
    genesis_id: str | None = None,
    note: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import AlgoAssetFreeze, AlgoCommon

    screen = AlgoCommon("Asset Freeze", ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_freeze", ButtonRequestType.ProtectCall)
    )
    screen = AlgoAssetFreeze(
        sender,
        rekey_to,
        fee,
        index,
        target,
        new_freeze_state,
        genesis_id,
        note,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_freeze", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_asset_xfer(
    ctx: wire.GenericContext,
    sender: str | None = None,
    receiver: str | None = None,
    index: str = 0,
    fee: str = 0,
    amount: str = 0,
    close_assets_to: str | None = None,
    revocation_target: str | None = None,
    rekey_to: str | None = None,
    genesis_id: str | None = None,
    note: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import AlgoAssetXfer, AlgoCommon

    screen = AlgoCommon("ASSET TRANSFER", ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_transfer", ButtonRequestType.ProtectCall)
    )
    screen = AlgoAssetXfer(
        sender,
        receiver,
        index,
        fee,
        amount,
        close_assets_to,
        revocation_target,
        rekey_to,
        genesis_id,
        note,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_transfer", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_asset_cfg(
    ctx: wire.GenericContext,
    fee: str,
    sender: str,
    index: str | None = None,
    total: str | None = None,
    default_frozen: bool = None,
    unit_name: str | None = None,
    asset_name: str | None = None,
    decimals: str | None = None,
    manager: str | None = None,
    reserve: str | None = None,
    freeze: str | None = None,
    clawback: str | None = None,
    url: str | None = None,
    metadata_hash: str | None = None,
    rekey_to: str | None = None,
    genesis_id: str | None = None,
    note: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import AlgoAssetCfg, AlgoCommon

    screen = AlgoCommon("ASSET CONFIG", ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_cfg", ButtonRequestType.ProtectCall)
    )
    screen = AlgoAssetCfg(
        fee,
        sender,
        index,
        total,
        default_frozen,
        unit_name,
        asset_name,
        decimals,
        manager,
        reserve,
        freeze,
        clawback,
        url,
        metadata_hash,
        rekey_to,
        genesis_id,
        note,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_asset_cfg", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_keyregNonparticipating(
    ctx: wire.GenericContext,
    sender: str,
    fee: str,
    nonpart: bool,
    rekey_to: str | None = None,
    genesis_id: str | None = None,
    note: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import AlgoKeyregNonp, AlgoCommon

    screen = AlgoCommon("KEYREG NO PARTICIPATING", ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_keyreg_Nonp", ButtonRequestType.ProtectCall)
    )
    screen = AlgoKeyregNonp(
        sender, fee, nonpart, rekey_to, genesis_id, note, ctx.primary_color
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_keyreg_Nonp", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_keyregOnline(
    ctx: wire.GenericContext,
    format: str,
    sender: str,
    fee: str,
    votekey: str | None = None,
    selkey: str | None = None,
    votefst: str | None = None,
    votelst: str | None = None,
    votekd: str | None = None,
    sprfkey: str | None = None,
    rekey_to: str | None = None,
    genesis_id: str | None = None,
    note: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import AlgoKeyregOnline, AlgoCommon

    screen = AlgoCommon(format, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "algo_keyreg_online", ButtonRequestType.ProtectCall)
    )
    screen = AlgoKeyregOnline(
        sender,
        fee,
        votekey,
        selkey,
        sprfkey,
        rekey_to,
        genesis_id,
        note,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "algo_keyreg_online", ButtonRequestType.ProtectCall)
    )


async def confirm_algo_app(ctx: wire.Context, signer: str, raw_message: bytes) -> None:

    from trezor.lvglui.scrs.template import AlgoApplication

    screen = AlgoApplication(signer, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "common_blinding_sign", ButtonRequestType.ProtectCall)
    )
    data_size = len(raw_message)
    await confirm_data(
        ctx,
        "confirm_data",
        title=_(i18n_keys.TITLE__VIEW_DATA),
        description=_(i18n_keys.SUBTITLE__STR_BYTES).format(data_size),
        data=raw_message,
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_ripple_payment(
    ctx: wire.GenericContext,
    sender: str | None = None,
    receiver: str | None = None,
    amount: str = 0,
    fee: str = 0,
    total: str | None = None,
    tag: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import RipplePayment

    screen = RipplePayment(
        _(i18n_keys.TITLE__SIGN_STR_TRANSACTION).format("XRP"),
        sender,
        receiver,
        amount,
        fee,
        total,
        tag,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "ripple_payment", ButtonRequestType.ProtectCall)
    )


async def confirm_filecoin_tx(
    ctx: wire.GenericContext,
    address: str,
    amount: str,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
) -> None:
    from trezor.lvglui.scrs.template import TransactionOverview

    await raise_if_cancelled(
        interact(
            ctx,
            TransactionOverview(
                _(i18n_keys.TITLE__STR_TRANSACTION).format("Filecoin"),
                amount,
                address,
                primary_color=ctx.primary_color,
                icon_path=ctx.icon_path,
            ),
            "confirm_output",
            br_code,
        )
    )


async def confirm_filecoin_payment(
    ctx: wire.GenericContext,
    sender: str | None = None,
    receiver: str | None = None,
    amount: str | None = None,
    gaslimit: str | None = None,
    gasfeecap: str | None = None,
    gaspremium: str | None = None,
    total_amount: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import FilecoinPayment

    screen = FilecoinPayment(
        _(i18n_keys.TITLE__VIEW_TRANSACTION),
        sender,
        receiver,
        amount,
        gaslimit,
        gasfeecap,
        gaspremium,
        total_amount,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "filecoin_payment", ButtonRequestType.ProtectCall)
    )


async def confirm_cosmos_tx(
    ctx: wire.GenericContext,
    title: str | None,
    value: str | None,
    address: str | None,
    amount: str | None,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
) -> None:
    from trezor.lvglui.scrs.template import CosmosTransactionOverview

    await raise_if_cancelled(
        interact(
            ctx,
            CosmosTransactionOverview(
                _(i18n_keys.TITLE__STR_TRANSACTION).format("Cosmos"),
                title,
                value,
                amount,
                address,
                primary_color=ctx.primary_color,
                icon_path=ctx.icon_path,
            ),
            "confirm_output",
            br_code,
        )
    )


async def confirm_cosmos_send(
    ctx: wire.GenericContext,
    fee: str,
    chain_id: str,
    chain_name: str | None,
    sender: str | None = None,
    receiver: str | None = None,
    amount: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import CosmosSend

    screen = CosmosSend(
        _(i18n_keys.TITLE__SEND),
        chain_id,
        chain_name,
        sender,
        receiver,
        amount,
        fee,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "cosmos_send", ButtonRequestType.ProtectCall)
    )


async def confirm_cosmos_delegate(
    ctx: wire.GenericContext,
    fee: str,
    chain_id: str,
    chain_name: str | None,
    delegator: str | None = None,
    validator: str | None = None,
    amount: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import CosmosDelegate

    screen = CosmosDelegate(
        _(i18n_keys.TITLE__DELEGATE),
        chain_id,
        chain_name,
        delegator,
        validator,
        amount,
        fee,
        primary_color=ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "cosmos_delegate", ButtonRequestType.ProtectCall)
    )


async def confirm_cosmos_sign_common(
    ctx: wire.GenericContext,
    chain_id: str,
    chain_name: str | None,
    signer: str | None,
    fee: str,
    msgs_item: dict,
    title: str,
    value: str,
) -> None:
    from trezor.lvglui.scrs.template import (
        CosmosSignCommon,
        CosmosSignContent,
        CosmosLongValue,
    )

    screen = CosmosSignCommon(chain_id, chain_name, signer, fee, title, value)
    await raise_if_cancelled(
        interact(ctx, screen, "cosmos_sign_common", ButtonRequestType.ProtectCall)
    )
    screen = CosmosSignContent(msgs_item)
    await raise_if_cancelled(
        interact(ctx, screen, "cosmos_sign_common", ButtonRequestType.ProtectCall)
    )

    for key, value in msgs_item.items():
        if len(value) > 80:
            screen = CosmosLongValue(key, value, ctx.primary_color)
            await raise_if_cancelled(
                interact(
                    ctx, screen, "cosmos_sign_common", ButtonRequestType.ProtectCall
                )
            )


async def confirm_cosmos_memo(
    ctx: wire.GenericContext, title: str, description: str, memo: str
) -> None:
    from trezor.lvglui.scrs.template import BlobDisPlay

    screen = BlobDisPlay(title, description, memo, None)
    await raise_if_cancelled(
        interact(ctx, screen, "cosmos_memo", ButtonRequestType.ProtectCall)
    )


async def confirm_cosmos_sign_combined(
    ctx: wire.GenericContext,
    chain_id: str,
    signer: str | None,
    fee: str,
    msgs: str,
) -> None:
    from trezor.lvglui.scrs.template import CosmosSignCombined

    screen = CosmosSignCombined(chain_id, signer, fee, msgs)
    await raise_if_cancelled(
        interact(
            ctx, screen, "confirm_cosmos_sign_combined", ButtonRequestType.ProtectCall
        )
    )


async def confirm_sign_typed_hash(
    ctx: wire.GenericContext, domain_hash: str, message_hash: str
) -> None:
    from trezor.lvglui.scrs.template import ConfirmTypedHash

    screen = ConfirmTypedHash(
        _(i18n_keys.TITLE__STR_TYPED_HASH).format(ctx.name),
        ctx.icon_path,
        domain_hash,
        message_hash,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_sign_typed_hash", ButtonRequestType.ProtectCall)
    )


async def show_bip39_dotmap(
    ctx: wire.GenericContext, mnemonics: bytes, recovery_check: bool = False
) -> None:
    from trezor.lvglui.scrs.common import FullSizeWindow, lv

    while True:
        ask_screen = FullSizeWindow(
            _(i18n_keys.TITLE__BACK_UP_WITH_KEYTAG),
            _(i18n_keys.SUBTITLE__BACK_UP_WITH_KEYTAG),
            confirm_text=_(i18n_keys.BUTTON__BACKUP),
            cancel_text=_(i18n_keys.BUTTON__NOT_NOW),
            icon_path="A:/res/icon_dotmap.png",
            anim_dir=0,
        )
        ask_screen.btn_no.set_size(464, 98)
        ask_screen.btn_no.align(lv.ALIGN.BOTTOM_MID, 0, -8)
        ask_screen.btn_yes.set_size(464, 98)
        ask_screen.btn_yes.align_to(ask_screen.btn_no, lv.ALIGN.OUT_TOP_MID, 0, -8)
        if await ask_screen.request():
            while True:
                from trezor.lvglui.scrs.bip39_dotmap import Bip39DotMap

                screen = Bip39DotMap(len(mnemonics.decode().split()))
                screen.show(mnemonics.decode())
                if await screen.request():
                    if recovery_check:
                        break
                    final_confirm = FullSizeWindow(
                        _(i18n_keys.TITLE__FINISH_KEYTAG_BACKUP),
                        _(i18n_keys.SUBTITLE__FINISH_KEYTAG_BACKUP),
                        confirm_text=_(i18n_keys.BUTTON__DONE),
                        cancel_text=_(i18n_keys.BUTTON__CANCEL),
                        icon_path="A:/res/icon_tips_blue.png",
                        anim_dir=0,
                    )
                    if await final_confirm.request():
                        break
            break
        else:
            if recovery_check:
                break
            confirm_screen = FullSizeWindow(
                _(i18n_keys.TITLE__SKIP_BACKUP),
                _(i18n_keys.SUBTITLE__SKIP_BACKUP),
                confirm_text=_(i18n_keys.BUTTON__SKIP),
                cancel_text=_(i18n_keys.BUTTON__CANCEL),
                icon_path="A:/res/icon_tips_blue.png",
                anim_dir=0,
            )
            if await confirm_screen.request():
                break


async def confirm_polkadot_balances(
    ctx: wire.GenericContext,
    chain_name: str,
    module: str,
    method: str,
    sender: str,
    dest: str,
    source: str | None = None,
    balance: str | None = None,
    tip: str | None = None,
    keep_alive: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import PolkadotBalances

    screen = PolkadotBalances(
        chain_name,
        module,
        method,
        sender,
        dest,
        source,
        balance,
        tip,
        keep_alive,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "polkadot_balance", ButtonRequestType.ProtectCall)
    )


async def confirm_tron_freeze(
    ctx: wire.GenericContext,
    title: str,
    sender: str,
    resource: str | None = None,
    balance: str | None = None,
    duration: str | None = None,
    receiver: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import TronAssetFreeze, AlgoCommon

    screen = AlgoCommon(title, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "tron_asset_freeze", ButtonRequestType.ProtectCall)
    )
    screen = TronAssetFreeze(
        True,
        sender,
        resource,
        balance,
        duration,
        receiver,
        None,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "tron_asset_freeze", ButtonRequestType.ProtectCall)
    )


async def confirm_tron_unfreeze(
    ctx: wire.GenericContext,
    title: str,
    sender: str,
    resource: str | None = None,
    balance: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import TronAssetFreeze, AlgoCommon

    screen = AlgoCommon(title, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "tron_asset_freeze_v2", ButtonRequestType.ProtectCall)
    )
    screen = TronAssetFreeze(
        False,
        sender,
        resource,
        balance,
        None,
        None,
        None,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "tron_asset_freeze_v2", ButtonRequestType.ProtectCall)
    )


async def confirm_tron_delegate(
    ctx: wire.GenericContext,
    title: str,
    sender: str,
    resource: str | None = None,
    balance: str | None = None,
    receiver: str | None = None,
    lock: str | None = None,
) -> None:
    from trezor.lvglui.scrs.template import TronAssetFreeze, AlgoCommon

    screen = AlgoCommon(title, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_tron_delegate", ButtonRequestType.ProtectCall)
    )
    screen = TronAssetFreeze(
        False,
        sender,
        resource,
        balance,
        None,
        receiver,
        lock,
        ctx.primary_color,
    )
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_tron_delegate", ButtonRequestType.ProtectCall)
    )


async def confirm_tron_common(
    ctx: wire.GenericContext,
    title: str,
) -> None:
    from trezor.lvglui.scrs.template import AlgoCommon

    screen = AlgoCommon(title, ctx.primary_color, ctx.icon_path)
    await raise_if_cancelled(
        interact(ctx, screen, "confirm_tron_common", ButtonRequestType.ProtectCall)
    )
