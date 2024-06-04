use crate::{
    error,
    micropython::{map::Map, obj::Obj, util},
    translations::TR,
    ui::{
        component::{
            swipe_detect::SwipeSettings,
            text::paragraphs::{Paragraph, Paragraphs},
            ComponentExt, SwipeDirection,
        },
        flow::{
            base::{DecisionBuilder as _, StateChange},
            FlowMsg, FlowState, SwipeFlow,
        },
        layout::obj::LayoutObj,
        model_mercury::component::SwipeContent,
    },
};

use super::super::{
    component::{Frame, FrameMsg, PromptScreen, VerticalMenu, VerticalMenuChoiceMsg},
    theme,
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ShowTutorial {
    StepWelcome,
    StepBegin,
    StepNavigation,
    StepMenu,
    StepHold,
    StepDone,
    Menu,
    DidYouKnow,
    HoldToExit,
}

impl FlowState for ShowTutorial {
    #[inline]
    fn index(&'static self) -> usize {
        *self as usize
    }

    fn handle_swipe(&'static self, direction: SwipeDirection) -> StateChange {
        match (self, direction) {
            (Self::StepBegin, SwipeDirection::Up) => Self::StepNavigation.swipe(direction),
            (Self::StepNavigation, SwipeDirection::Up) => Self::StepMenu.swipe(direction),
            (Self::StepNavigation, SwipeDirection::Down) => Self::StepBegin.swipe(direction),
            (Self::StepMenu, SwipeDirection::Up) => Self::StepHold.swipe(direction),
            (Self::StepMenu, SwipeDirection::Down) => Self::StepNavigation.swipe(direction),
            (Self::StepMenu, SwipeDirection::Left) => Self::Menu.swipe(direction),
            (Self::Menu, SwipeDirection::Left) => Self::DidYouKnow.swipe(direction),
            (Self::Menu, SwipeDirection::Right) => Self::StepBegin.swipe(direction),
            (Self::DidYouKnow, SwipeDirection::Right) => Self::Menu.swipe(direction),
            (Self::StepDone, SwipeDirection::Up) => self.return_msg(FlowMsg::Confirmed),
            _ => self.do_nothing(),
        }
    }

    fn handle_event(&'static self, msg: FlowMsg) -> StateChange {
        match (self, msg) {
            (Self::StepWelcome, FlowMsg::Confirmed) => Self::StepBegin.swipe_up(),
            (Self::StepMenu, FlowMsg::Info) => Self::Menu.swipe_left(),
            (Self::Menu, FlowMsg::Choice(0)) => Self::DidYouKnow.swipe_left(),
            (Self::Menu, FlowMsg::Choice(1)) => Self::StepBegin.swipe_right(),
            (Self::Menu, FlowMsg::Choice(2)) => Self::HoldToExit.swipe_up(),
            (Self::Menu, FlowMsg::Cancelled) => Self::StepMenu.swipe_right(),
            (Self::DidYouKnow, FlowMsg::Cancelled) => Self::Menu.swipe_right(),
            (Self::StepHold, FlowMsg::Confirmed) => Self::StepDone.swipe_up(),
            (Self::HoldToExit, FlowMsg::Confirmed) => Self::StepDone.swipe_up(),
            _ => self.do_nothing(),
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn new_show_tutorial(_n_args: usize, _args: *const Obj, _kwargs: *mut Map) -> Obj {
    unsafe { util::try_or_raise(ShowTutorial::new_obj) }
}

impl ShowTutorial {
    fn new_obj() -> Result<Obj, error::Error> {
        let content_step_welcome = Frame::left_aligned(
            TR::tutorial__welcome_safe5.into(),
            SwipeContent::new(PromptScreen::new_tap_to_start()),
        )
        .with_footer(TR::instructions__tap_to_start.into(), None)
        .map(|msg| matches!(msg, FrameMsg::Content(())).then_some(FlowMsg::Confirmed));

        let content_step_begin = Frame::left_aligned(
            TR::tutorial__title_lets_begin.into(),
            SwipeContent::new(Paragraphs::new(Paragraph::new(
                &theme::TEXT_MAIN_GREY_LIGHT,
                TR::tutorial__lets_begin,
            ))),
        )
        .with_footer(
            TR::instructions__swipe_up.into(),
            Some(TR::tutorial__get_started.into()),
        )
        .with_swipe(SwipeDirection::Up, SwipeSettings::default())
        .map(|_| None);

        let content_step_navigation = Frame::left_aligned(
            TR::tutorial__title_easy_navigation.into(),
            SwipeContent::new(Paragraphs::new(Paragraph::new(
                &theme::TEXT_MAIN_GREY_LIGHT,
                TR::tutorial__swipe_up_and_down,
            ))),
        )
        .with_footer(
            TR::instructions__swipe_up.into(),
            Some(TR::tutorial__continue.into()),
        )
        .with_swipe(SwipeDirection::Up, SwipeSettings::default())
        .with_swipe(SwipeDirection::Down, SwipeSettings::default())
        .map(|_| None);

        let content_step_menu = Frame::left_aligned(
            TR::tutorial__title_handy_menu.into(),
            SwipeContent::new(Paragraphs::new(Paragraph::new(
                &theme::TEXT_MAIN_GREY_LIGHT,
                TR::tutorial__menu,
            ))),
        )
        .with_menu_button()
        .button_styled(theme::button_warning_low())
        .with_footer(
            TR::instructions__swipe_up.into(),
            Some(TR::buttons__continue.into()),
        )
        .with_swipe(SwipeDirection::Up, SwipeSettings::default())
        .with_swipe(SwipeDirection::Down, SwipeSettings::default())
        .map(|msg| matches!(msg, FrameMsg::Button(_)).then_some(FlowMsg::Info));

        let content_step_hold = Frame::left_aligned(
            TR::tutorial__title_hold.into(),
            SwipeContent::new(PromptScreen::new_hold_to_confirm()),
        )
        .with_footer(TR::instructions__exit_tutorial.into(), None)
        .map(|msg| matches!(msg, FrameMsg::Content(())).then_some(FlowMsg::Confirmed));

        let content_step_done = Frame::left_aligned(
            TR::tutorial__title_well_done.into(),
            SwipeContent::new(Paragraphs::new(Paragraph::new(
                &theme::TEXT_MAIN_GREY_LIGHT,
                TR::tutorial__ready_to_use_safe5,
            ))),
        )
        .with_footer(TR::instructions__swipe_up.into(), None)
        .with_swipe(SwipeDirection::Up, SwipeSettings::default())
        .map(|_| None);

        let content_menu = Frame::left_aligned(
            "".into(),
            VerticalMenu::empty()
                .item(theme::ICON_CHEVRON_RIGHT, TR::tutorial__did_you_know.into())
                .item(theme::ICON_REBOOT, TR::tutorial__restart_tutorial.into())
                .danger(theme::ICON_CANCEL, TR::tutorial__exit.into()),
        )
        .with_cancel_button()
        .with_swipe(SwipeDirection::Right, SwipeSettings::immediate())
        .with_swipe(SwipeDirection::Left, SwipeSettings::immediate())
        .map(|msg| match msg {
            FrameMsg::Content(VerticalMenuChoiceMsg::Selected(i)) => Some(FlowMsg::Choice(i)),
            FrameMsg::Button(_) => Some(FlowMsg::Cancelled),
        });

        let content_did_you_know = Frame::left_aligned(
            "".into(),
            SwipeContent::new(Paragraphs::new(Paragraph::new(
                &theme::TEXT_MAIN_GREY_LIGHT,
                TR::tutorial__first_wallet,
            ))),
        )
        .with_cancel_button()
        .with_swipe(SwipeDirection::Right, SwipeSettings::immediate())
        .map(|msg| matches!(msg, FrameMsg::Button(_)).then_some(FlowMsg::Cancelled));

        let content_hold_to_exit = Frame::left_aligned(
            TR::tutorial__title_hold.into(),
            SwipeContent::new(PromptScreen::new_hold_to_confirm_danger()),
        )
        .with_footer(TR::instructions__exit_tutorial.into(), None)
        .map(|msg| matches!(msg, FrameMsg::Content(())).then_some(FlowMsg::Confirmed));

        let res = SwipeFlow::new(&ShowTutorial::StepWelcome)?
            .with_page(&ShowTutorial::StepWelcome, content_step_welcome)?
            .with_page(&ShowTutorial::StepBegin, content_step_begin)?
            .with_page(&ShowTutorial::StepNavigation, content_step_navigation)?
            .with_page(&ShowTutorial::StepMenu, content_step_menu)?
            .with_page(&ShowTutorial::StepHold, content_step_hold)?
            .with_page(&ShowTutorial::StepDone, content_step_done)?
            .with_page(&ShowTutorial::Menu, content_menu)?
            .with_page(&ShowTutorial::DidYouKnow, content_did_you_know)?
            .with_page(&ShowTutorial::HoldToExit, content_hold_to_exit)?;
        Ok(LayoutObj::new(res)?.into())
    }
}
